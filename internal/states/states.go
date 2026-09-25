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
	"example.com/vuln-analyzer/internal/rootcause"
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

type ResolveRootCause struct {
	Manual   []domain.RootCause
	Resolver *rootcause.Resolver
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
	model, evs, err := h.Resolver.Resolve(ctx, c.Vulnerability)
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

type BuildExploitModel struct {
	ModelPath string
}

func (BuildExploitModel) State() domain.WorkflowState { return domain.StateBuildExploitModel }

func (h BuildExploitModel) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.ModelPath == "" {
		return workflow.Transition{
			Next:   domain.StateInconclusive,
			Reason: "exploit model builder not implemented (slice 5); provide --exploit-model",
		}, nil
	}
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
		if seen[cond.ID] || cond.Subject == nil {
			continue
		}
		if !needsProvenance(cond.Kind) {
			continue
		}
		seen[cond.ID] = true
		h.collectProvenance(ctx, c, cond)
	}
}

func needsProvenance(k domain.ConditionKind) bool {
	switch k {
	case domain.ConditionAttackerControl, domain.ConditionInputConstraint, domain.ConditionValidation:
		return true
	}
	return false
}

func (h CollectEvidence) collectProvenance(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition) {
	sites, err := h.Source.FindCallers(ctx, *cond.Subject)
	if err != nil {
		c.EvidenceGraph.ToolLimitations = append(c.EvidenceGraph.ToolLimitations,
			fmt.Sprintf("find_callers %s.%s: %v", cond.Subject.Package, cond.Subject.Symbol, err))
		return
	}
	if len(sites) == 0 {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			fmt.Sprintf("no call sites of %s.%s found in product packages", cond.Subject.Package, cond.Subject.Symbol))
		return
	}
	for _, site := range sites {
		flow, evs, err := h.Source.TraceArgument(ctx, site, cond.ArgIndex)
		if err != nil {
			c.EvidenceGraph.ToolLimitations = append(c.EvidenceGraph.ToolLimitations,
				fmt.Sprintf("trace_argument %s:%d: %v", site.File, site.Line, err))
			continue
		}
		flow.ConditionID = cond.ID
		c.EvidenceGraph.DataFlows = append(c.EvidenceGraph.DataFlows, flow)
		for _, e := range evs {
			c.EvidenceGraph.AddEvidence(e)
		}
		vals, vev, err := h.Source.FindValidations(ctx, site, cond.ArgIndex)
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
		subject := claimSubject(cond, c)
		if cond == nil || subject == nil {
			cl.NegativeVerification = &domain.NegativeVerification{
				Status: domain.NegativeInsufficientScope,
				Notes:  "cannot resolve condition subject for falsification",
			}
			continue
		}
		updated := h.Verifier.VerifyFalse(ctx, c, *cl, *cond, *subject)
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
	return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "negative verification applied"}, nil
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

func claimSubject(cond *domain.Condition, c *domain.AnalysisCase) *domain.SymbolRef {
	if cond != nil && cond.Subject != nil {
		return cond.Subject
	}
	if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
		rc := c.RootCause.RootCauses[0]
		return &domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol}
	}
	return nil
}

type Review struct{}

func (Review) State() domain.WorkflowState { return domain.StateReview }

func (Review) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
		"reviewer not configured; proposed verdict not reviewed")
	return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review skipped: no reviewer"}, nil
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
	Dir string
}

func (BuildReport) State() domain.WorkflowState { return domain.StateBuildReport }

func (h BuildReport) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if err := report.Write(h.Dir, c); err != nil {
		return workflow.Transition{}, fmt.Errorf("build report: %w", err)
	}
	return workflow.Transition{Next: domain.StateCompleted, Reason: "report written to " + h.Dir}, nil
}
