// Package states implements the workflow StateHandlers for the deterministic
// slices of the analyzer. States whose automation belongs to later milestones
// terminate honestly at INCONCLUSIVE instead of pretending analysis happened.
package states

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/evaluator"
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/report"
	"example.com/vuln-analyzer/internal/repository"
	"example.com/vuln-analyzer/internal/review"
	"example.com/vuln-analyzer/internal/rootcause"
	"example.com/vuln-analyzer/internal/tracker"
	"example.com/vuln-analyzer/internal/vulnerability"
	"example.com/vuln-analyzer/internal/workflow"
)

type Created struct{}

func (Created) State() domain.WorkflowState { return domain.StateCreated }

func (Created) Run(context.Context, *domain.AnalysisCase) (workflow.Transition, error) {
	return workflow.Transition{Next: domain.StateSnapshotProduct, Reason: "case created"}, nil
}

type SnapshotProduct struct {
	Repo    repository.Snapshotter
	Path    string
	Options repository.SnapshotOptions
}

func (SnapshotProduct) State() domain.WorkflowState { return domain.StateSnapshotProduct }

func (h SnapshotProduct) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	snap, err := h.Repo.Snapshot(ctx, h.Path, h.Options)
	if err != nil {
		return workflow.Transition{
			Next:   domain.StateFailed,
			Reason: fmt.Sprintf("product snapshot failed (commit is mandatory for a verdict): %v", err),
		}, nil
	}
	c.Product = snap
	return workflow.Transition{Next: domain.StateResolveVulnerability, Reason: "product snapshot captured"}, nil
}

type ResolveVulnerability struct {
	Source vulnerability.Source
	ID     string
}

func (ResolveVulnerability) State() domain.WorkflowState { return domain.StateResolveVulnerability }

func (h ResolveVulnerability) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	v, err := h.Source.Get(ctx, h.ID)
	if err != nil {
		return workflow.Transition{
			Next:   domain.StateFailed,
			Reason: fmt.Sprintf("vulnerability resolution failed: %v", err),
		}, nil
	}
	c.Vulnerability = *v
	return workflow.Transition{Next: domain.StateCheckAffected, Reason: "vulnerability normalized"}, nil
}

type CheckAffected struct {
	Resolver affected.Resolver
}

func (CheckAffected) State() domain.WorkflowState { return domain.StateCheckAffected }

func (h CheckAffected) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	res, ev, err := h.Resolver.Resolve(ctx, c.Vulnerability, c.Product)
	if err != nil {
		return workflow.Transition{}, err
	}
	c.Affected = &res
	for _, e := range ev {
		id := c.EvidenceGraph.AddEvidence(e)
		_ = id
	}
	c.EvidenceGraph.ComputeHash()
	if res.ModulePresent == domain.ClaimFalse ||
		res.VersionAffected == domain.ClaimFalse ||
		res.PackagePresent == domain.ClaimFalse ||
		res.BuildRelevant == domain.ClaimFalse {
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "deterministic negative: component not applicable"}, nil
	}
	return workflow.Transition{Next: domain.StateResolveRootCause, Reason: "affected chain not refuted"}, nil
}

// RootCauseResolver produces a root cause model — deterministic or
// LLM-assisted. LLM proposals still pass through Verifier.
type RootCauseResolver interface {
	Resolve(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error)
}

type ResolveRootCause struct {
	Manual   []domain.RootCause
	Resolver RootCauseResolver
	Verifier *rootcause.Verifier
}

func (ResolveRootCause) State() domain.WorkflowState { return domain.StateResolveRootCause }

func (h ResolveRootCause) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if len(h.Manual) > 0 {
		c.RootCause = &domain.RootCauseModel{
			Status:     domain.RootCauseResolved,
			RootCauses: h.Manual,
			Limitations: []string{
				"root cause provided manually; symbol existence verified only if verifier configured",
			},
		}
		if h.Verifier != nil {
			c.RootCause.Limitations = append(c.RootCause.Limitations,
				h.Verifier.Verify(ctx, c.RootCause, c.Vulnerability)...)
			if c.RootCause.Status != domain.RootCauseResolved {
				return workflow.Transition{
					Next:   domain.StateInconclusive,
					Reason: "manual root cause failed verification",
				}, nil
			}
		}
		return workflow.Transition{Next: domain.StateBuildExploitModel, Reason: "manual root cause accepted"}, nil
	}
	if h.Resolver == nil {
		return workflow.Transition{
			Next:   domain.StateInconclusive,
			Reason: "root cause unresolved: no resolver configured and --root-cause not provided",
		}, nil
	}
	model, evs, err := h.Resolver.Resolve(ctx, c, c.Vulnerability)
	if err != nil {
		return workflow.Transition{}, fmt.Errorf("root cause resolve: %w", err)
	}
	for _, e := range evs {
		c.EvidenceGraph.AddEvidence(e)
	}
	if h.Verifier != nil && len(model.RootCauses) > 0 {
		model.Limitations = append(model.Limitations,
			h.Verifier.Verify(ctx, model, c.Vulnerability)...)
	}
	c.RootCause = model
	c.EvidenceGraph.ComputeHash()
	if model.Status != domain.RootCauseResolved {
		return workflow.Transition{
			Next:   domain.StateInconclusive,
			Reason: fmt.Sprintf("root cause %s: %s", model.Status, strings.Join(model.Limitations, "; ")),
		}, nil
	}
	return workflow.Transition{Next: domain.StateBuildExploitModel, Reason: "root cause resolved from advisory/fix evidence"}, nil
}

// ExploitBuilder builds an exploit model from a resolved root cause.
type ExploitBuilder interface {
	Build(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability, rc *domain.RootCauseModel) (*domain.ExploitModel, []string)
}

type BuildExploitModel struct {
	ModelPath string
	Builder   ExploitBuilder
}

func (BuildExploitModel) State() domain.WorkflowState { return domain.StateBuildExploitModel }

func (h BuildExploitModel) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.ModelPath != "" {
		b, err := os.ReadFile(h.ModelPath)
		if err != nil {
			return workflow.Transition{}, fmt.Errorf("read exploit model: %w", err)
		}
		var m domain.ExploitModel
		if err := json.Unmarshal(b, &m); err != nil {
			return workflow.Transition{
				Next:   domain.StateInconclusive,
				Reason: fmt.Sprintf("exploit model file is invalid: %v", err),
			}, nil
		}
		if len(m.MandatoryConditions) == 0 {
			return workflow.Transition{
				Next:   domain.StateInconclusive,
				Reason: "exploit model has no mandatory conditions",
			}, nil
		}
		c.Exploit = &m
		return workflow.Transition{Next: domain.StateCollectEvidence, Reason: "exploit model loaded"}, nil
	}
	if h.Builder == nil || c.RootCause == nil {
		return workflow.Transition{
			Next:   domain.StateInconclusive,
			Reason: "no exploit model: provide --exploit-model or configure a builder",
		}, nil
	}
	m, limitations := h.Builder.Build(ctx, c, c.Vulnerability, c.RootCause)
	if m == nil {
		return workflow.Transition{
			Next:   domain.StateInconclusive,
			Reason: "exploit model could not be built: " + strings.Join(limitations, "; "),
		}, nil
	}
	c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations, limitations...)
	c.Exploit = m
	return workflow.Transition{Next: domain.StateCollectEvidence, Reason: "exploit model built from root causes"}, nil
}

type CollectEvidence struct {
	Govulncheck goanalysis.Runner
	Source      *goanalysis.Index
}

func (CollectEvidence) State() domain.WorkflowState { return domain.StateCollectEvidence }

func (h CollectEvidence) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.Govulncheck != nil {
		h.runGovulncheck(ctx, c)
	}
	if h.Source != nil {
		h.runSourceAnalysis(ctx, c)
	}
	if h.Govulncheck == nil && h.Source == nil {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			"no evidence collectors beyond affected resolution are wired yet")
	}
	c.EvidenceGraph.ComputeHash()
	return workflow.Transition{Next: domain.StateEvaluateConditions, Reason: "deterministic evidence collection complete"}, nil
}

func (h CollectEvidence) runGovulncheck(ctx context.Context, c *domain.AnalysisCase) {
	raw, err := h.Govulncheck.RunGovulncheck(ctx, c.Product.Repository, c.Product)
	if err != nil {
		c.EvidenceGraph.ToolLimitations = append(c.EvidenceGraph.ToolLimitations,
			fmt.Sprintf("govulncheck failed: %v", err))
		return
	}
	evID := c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceGovulncheck,
		Quality: domain.QualityDeterministic,
		Source:  "govulncheck -json -mode source ./...",
		Tool:    "govulncheck",
		Command: "govulncheck -json -mode source ./...",
		Content: string(raw),
	})
	res, err := goanalysis.Parse(raw)
	if err != nil {
		c.EvidenceGraph.ToolLimitations = append(c.EvidenceGraph.ToolLimitations, err.Error())
		return
	}
	for _, f := range res.ForVulnerability(c.Vulnerability) {
		cp := f.CallPath()
		cp.EvidenceID = evID
		c.EvidenceGraph.CallPaths = append(c.EvidenceGraph.CallPaths, cp)
	}
}

// runSourceAnalysis gathers call sites, argument provenance and validations
// for conditions that carry a subject symbol.
func (h CollectEvidence) runSourceAnalysis(ctx context.Context, c *domain.AnalysisCase) {
	if c.Exploit == nil {
		return
	}
	if err := h.Source.Loaded(ctx); err != nil {
		c.EvidenceGraph.ToolLimitations = append(c.EvidenceGraph.ToolLimitations,
			fmt.Sprintf("source index load failed: %v", err))
		return
	}
	conds := append([]domain.Condition{}, c.Exploit.MandatoryConditions...)
	conds = append(conds, c.Exploit.SupportingFactors...)
	seen := map[domain.ConditionID]bool{}
	for _, cond := range conds {
		if seen[cond.ID] || !needsProvenance(cond.Kind) {
			continue
		}
		seen[cond.ID] = true
		subjects := cond.Subjects
		if cond.Subject != nil {
			subjects = append(append([]domain.SymbolRef{}, subjects...), *cond.Subject)
		}
		for _, subj := range dedupSubjects(subjects) {
			h.collectProvenance(ctx, c, cond, subj)
		}
	}
}

func dedupSubjects(in []domain.SymbolRef) []domain.SymbolRef {
	seen := map[string]bool{}
	var out []domain.SymbolRef
	for _, s := range in {
		k := s.Package + "." + s.Symbol
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// traceArgs traces a single argument (ArgIndex >= 0) or every argument
// (ArgIndex < 0, when the input parameter is unknown) at a call site.
func (h CollectEvidence) traceArgs(ctx context.Context, site domain.CallSite, cond domain.Condition) ([]domain.DataFlow, []domain.Evidence, error) {
	if cond.ArgIndex < 0 {
		return h.Source.TraceAllArguments(ctx, site)
	}
	flow, evs, err := h.Source.TraceArgument(ctx, site, cond.ArgIndex)
	if err != nil {
		return nil, nil, err
	}
	return []domain.DataFlow{flow}, evs, nil
}

func needsProvenance(k domain.ConditionKind) bool {
	switch k {
	case domain.ConditionAttackerControl, domain.ConditionInputConstraint, domain.ConditionValidation:
		return true
	}
	return false
}

func (h CollectEvidence) collectProvenance(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition, subj domain.SymbolRef) {
	sites, err := h.Source.FindCallers(ctx, subj)
	if err != nil {
		c.EvidenceGraph.ToolLimitations = append(c.EvidenceGraph.ToolLimitations,
			fmt.Sprintf("find_callers %s.%s: %v", subj.Package, subj.Symbol, err))
		return
	}
	if len(sites) == 0 {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			fmt.Sprintf("no call sites of %s.%s found in product packages", subj.Package, subj.Symbol))
		return
	}
	for _, site := range sites {
		flows, evs, err := h.traceArgs(ctx, site, cond)
		if err != nil {
			c.EvidenceGraph.ToolLimitations = append(c.EvidenceGraph.ToolLimitations,
				fmt.Sprintf("trace_argument %s:%d: %v", site.File, site.Line, err))
			continue
		}
		for _, flow := range flows {
			flow.ConditionID = cond.ID
			c.EvidenceGraph.DataFlows = append(c.EvidenceGraph.DataFlows, flow)
		}
		for _, e := range evs {
			c.EvidenceGraph.AddEvidence(e)
		}
		argIdx := cond.ArgIndex
		if argIdx < 0 {
			argIdx = 0
		}
		vals, vev, err := h.Source.FindValidations(ctx, site, argIdx)
		if err == nil {
			for _, v := range vals {
				v.Property = fmt.Sprintf("cond=%s %s", cond.ID, v.Property)
				c.EvidenceGraph.Validations = append(c.EvidenceGraph.Validations, v)
			}
			for _, e := range vev {
				c.EvidenceGraph.AddEvidence(e)
			}
		}
	}
}

type EvaluateConditions struct {
	Evaluators []evaluator.ConditionEvaluator
	// Fallback (e.g. the LLM agent) runs on conditions that deterministic
	// evaluators left UNKNOWN.
	Fallback evaluator.ConditionEvaluator
}

func (EvaluateConditions) State() domain.WorkflowState { return domain.StateEvaluateConditions }

func (h EvaluateConditions) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if c.Exploit == nil {
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "no exploit model"}, nil
	}
	existing := map[domain.ConditionID]bool{}
	for _, cl := range c.Claims {
		existing[cl.ConditionID] = true
	}
	hasFalse := false
	for _, cond := range c.Exploit.MandatoryConditions {
		if existing[cond.ID] {
			if claim := findClaim(c.Claims, cond.ID); claim != nil && claim.Result == domain.ClaimFalse {
				hasFalse = true
			}
			continue
		}
		claim := domain.Claim{
			ID:          domain.ClaimID("CL-" + string(cond.ID)),
			ConditionID: cond.ID,
			Result:      domain.ClaimUnknown,
			Limitations: []string{"no evaluator handled this condition"},
		}
		for _, ev := range h.Evaluators {
			if ev.CanEvaluate(cond) {
				claim = ev.Evaluate(cond, c)
				break
			}
		}
		if claim.Result == domain.ClaimUnknown && h.Fallback != nil && h.Fallback.CanEvaluate(cond) {
			alt := h.Fallback.Evaluate(cond, c)
			if alt.Result != domain.ClaimUnknown || len(alt.EvidenceIDs) > 0 {
				claim = alt
			}
		}
		if claim.Result == domain.ClaimFalse {
			hasFalse = true
		}
		c.Claims = append(c.Claims, claim)
	}
	if hasFalse {
		return workflow.Transition{Next: domain.StateNegativeCheck, Reason: "candidate FALSE requires negative verification"}, nil
	}
	if allMandatoryTrue(c) {
		return workflow.Transition{Next: domain.StateReview, Reason: "all mandatory conditions satisfied"}, nil
	}
	return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "unresolved mandatory conditions"}, nil
}

func findClaim(claims []domain.Claim, id domain.ConditionID) *domain.Claim {
	for i := range claims {
		if claims[i].ConditionID == id {
			return &claims[i]
		}
	}
	return nil
}

func allMandatoryTrue(c *domain.AnalysisCase) bool {
	if c.Exploit == nil || len(c.Exploit.MandatoryConditions) == 0 {
		return false
	}
	for _, cond := range c.Exploit.MandatoryConditions {
		claim := findClaim(c.Claims, cond.ID)
		if claim == nil || claim.Result != domain.ClaimTrue {
			return false
		}
	}
	return true
}

type NegativeCheck struct {
	Verifier *goanalysis.Verifier
}

func (NegativeCheck) State() domain.WorkflowState { return domain.StateNegativeCheck }

func (h NegativeCheck) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	for i := range c.Claims {
		cl := &c.Claims[i]
		if cl.Result != domain.ClaimFalse || cl.NegativeVerification != nil {
			continue
		}
		if h.Verifier == nil {
			cl.NegativeVerification = &domain.NegativeVerification{
				Status:      domain.NegativeInsufficientScope,
				Limitations: []string{"negative verifier not configured"},
			}
			continue
		}
		cond := findCondition(c.Exploit, cl.ConditionID)
		if cond == nil {
			cl.NegativeVerification = &domain.NegativeVerification{
				Status: domain.NegativeInsufficientScope,
				Notes:  "cannot resolve condition for falsification",
			}
			continue
		}
		updated := h.Verifier.VerifyFalse(ctx, c, *cl, *cond)
		if updated.NegativeVerification != nil &&
			updated.NegativeVerification.Status == domain.NegativeContradicted {
			// the falsification attempt found a counterexample: the FALSE
			// claim cannot stand; demote it to UNKNOWN with the reason.
			updated.Limitations = append(updated.Limitations,
				"false claim contradicted by negative verification")
		}
		*cl = updated
	}
	c.EvidenceGraph.ComputeHash()
	return workflow.Transition{Next: domain.StateReview, Reason: "negative verification applied"}, nil
}

func findCondition(m *domain.ExploitModel, id domain.ConditionID) *domain.Condition {
	if m == nil {
		return nil
	}
	for i := range m.MandatoryConditions {
		if m.MandatoryConditions[i].ID == id {
			return &m.MandatoryConditions[i]
		}
	}
	for i := range m.SupportingFactors {
		if m.SupportingFactors[i].ID == id {
			return &m.SupportingFactors[i]
		}
	}
	return nil
}

type Review struct {
	Reviewer  review.Reviewer
	Evaluator evaluator.VerdictEvaluator
}

func (Review) State() domain.WorkflowState { return domain.StateReview }

func (h Review) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.Reviewer == nil {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			"reviewer not configured; proposed verdict not reviewed")
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review skipped: no reviewer"}, nil
	}
	maxIt := c.Workflow.Limits.MaxReviewIterations
	if maxIt <= 0 {
		maxIt = 2
	}
	if len(c.Reviews) >= maxIt {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			"review iteration budget exhausted; verdict computed on repaired claims")
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review budget exhausted"}, nil
	}

	// The proposed verdict is computed deterministically before review;
	// the reviewer may only repair claims, never set the verdict.
	proposed := h.Evaluator.Evaluate(affectedOf(c), exploitOf(c), c.Claims)
	rev := h.Reviewer.Review(c, proposed)
	rev.ID = domain.ReviewID(fmt.Sprintf("REV-%d", len(c.Reviews)+1))
	c.Reviews = append(c.Reviews, rev)
	c.Workflow.Usage.ReviewIterations++
	c.EvidenceGraph.ComputeHash()

	if rev.Result != domain.ReviewRevise {
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review ACCEPT"}, nil
	}
	// Repair: demote claims flagged high-severity to UNKNOWN. This is the
	// bounded repair — it only removes unsupported strength, never adds.
	repaired := false
	for _, f := range rev.Findings {
		if f.TargetType != "claim" || f.Severity != "high" {
			continue
		}
		for i := range c.Claims {
			if string(c.Claims[i].ID) == f.TargetID && c.Claims[i].Result != domain.ClaimUnknown {
				c.Claims[i].Result = domain.ClaimUnknown
				c.Claims[i].Limitations = append(c.Claims[i].Limitations,
					"demoted by reviewer: "+f.Problem)
				repaired = true
			}
		}
	}
	reason := "review REVISE: repaired claims"
	if !repaired {
		reason = "review REVISE: no repairable claims"
	}
	return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: reason}, nil
}

func affectedOf(c *domain.AnalysisCase) domain.AffectedResult {
	if c.Affected != nil {
		return *c.Affected
	}
	return domain.AffectedResult{}
}

func exploitOf(c *domain.AnalysisCase) domain.ExploitModel {
	if c.Exploit != nil {
		return *c.Exploit
	}
	return domain.ExploitModel{}
}

type EvaluateVerdict struct {
	Evaluator evaluator.VerdictEvaluator
}

func (EvaluateVerdict) State() domain.WorkflowState { return domain.StateEvaluateVerdict }

func (h EvaluateVerdict) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	var affected domain.AffectedResult
	if c.Affected != nil {
		affected = *c.Affected
	}
	var model domain.ExploitModel
	if c.Exploit != nil {
		model = *c.Exploit
	}
	v := h.Evaluator.Evaluate(affected, model, c.Claims)
	v.Limitations = append(v.Limitations, c.EvidenceGraph.Limitations...)
	c.Verdict = &v
	return workflow.Transition{Next: domain.StateBuildReport, Reason: "verdict evaluated: " + string(v.Verdict)}, nil
}

type BuildReport struct {
	Dir     string
	Tracker tracker.Sink
}

func (BuildReport) State() domain.WorkflowState { return domain.StateBuildReport }

func (h BuildReport) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if err := report.Write(h.Dir, c); err != nil {
		return workflow.Transition{}, fmt.Errorf("build report: %w", err)
	}
	if h.Tracker != nil {
		if err := h.Tracker.Publish(ctx, string(c.ID), report.Markdown(c)); err != nil {
			c.EvidenceGraph.ToolLimitations = append(c.EvidenceGraph.ToolLimitations,
				"tracker publish failed: "+err.Error())
		}
	}
	return workflow.Transition{Next: domain.StateCompleted, Reason: "report written to " + h.Dir}, nil
}
