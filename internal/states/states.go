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
	"sync"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/evaluator"
	"example.com/vuln-analyzer/internal/exposure"
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/report"
	"example.com/vuln-analyzer/internal/repository"
	"example.com/vuln-analyzer/internal/review"
	"example.com/vuln-analyzer/internal/rootcause"
	"example.com/vuln-analyzer/internal/toolaudit"
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
	c.EvidenceGraph.AddRuntimeEvidence(domain.Evidence{
		Quality: domain.QualityAuthoritative,
		Source:  "product snapshot",
		Content: fmt.Sprintf("go_version=%q goos=%s goarch=%s release_toolchain=%q go_mod=%q build_tags=%v",
			snap.GoVersion, snap.GOOS, snap.GOARCH, snap.ReleaseGoVersion, snap.GoModDirective, snap.BuildTags),
	})
	if snap.BinaryPath != "" {
		if info, err := repository.BinaryBuildInfo(ctx, snap.BinaryPath); err == nil {
			c.EvidenceGraph.AddRuntimeEvidence(domain.Evidence{
				Quality: domain.QualityAuthoritative,
				Source:  "binary build info",
				File:    snap.BinaryPath,
				Tool:    "go",
				Command: "go version -m " + snap.BinaryPath,
				Content: info,
			})
		} else {
			c.EvidenceGraph.AddLimitation("binary build info unavailable: " + err.Error())
		}
	}
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
// RootCauseProposer is an optional resolver extension: when every
// resolved candidate fails verification, the state asks it once for
// alternative candidates and verifies those the same way.
type RootCauseProposer interface {
	Propose(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability) ([]domain.RootCause, []string, error)
}

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
	// Candidates may fail source verification (e.g. a symbol added only by
	// the fix commit). If the resolver can propose fresh candidates, ask
	// once and verify those through the same verifier.
	if model.Status != domain.RootCauseResolved && h.Verifier != nil {
		if p, ok := h.Resolver.(RootCauseProposer); ok {
			props, lims, err := p.Propose(ctx, c, c.Vulnerability)
			model.Limitations = append(model.Limitations, lims...)
			if err == nil && len(props) > 0 {
				model.RootCauses = props
				model.Limitations = append(model.Limitations,
					h.Verifier.Verify(ctx, model, c.Vulnerability)...)
				if len(model.RootCauses) > 0 {
					model.Status = domain.RootCauseResolved
				}
			}
		}
	}
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
	for _, l := range limitations {
		c.EvidenceGraph.AddLimitation(l)
	}
	c.Exploit = m
	return workflow.Transition{Next: domain.StateCollectEvidence, Reason: "exploit model built from root causes"}, nil
}

type CollectEvidence struct {
	Govulncheck goanalysis.Runner
	Source      *goanalysis.Index
	// OSVBase, when set, lets coverage checks ask the vulnerability database
	// whether the advisory exists as a GO-* record — distinguishing
	// "evaluated, no path" from "unknown to the DB".
	OSVBase string
}

func (CollectEvidence) State() domain.WorkflowState { return domain.StateCollectEvidence }

func (h CollectEvidence) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.Govulncheck != nil {
		h.runGovulncheck(ctx, c)
	}
	if h.Source != nil {
		h.runSourceAnalysis(ctx, c)
		h.runListenerScan(ctx, c)
		h.runModuleUsage(ctx, c)
		h.runExposure(ctx, c)
	}
	if h.Govulncheck == nil && h.Source == nil {
		c.EvidenceGraph.AddLimitation("no evidence collectors beyond affected resolution are wired yet")
	}
	if isStdlibModule(c.Vulnerability.Module) {
		if c.Product.ReleaseGoVersion != "" {
			c.EvidenceGraph.AddLimitation(fmt.Sprintf(
				"stdlib advisory assessed against release toolchain %s (analysis toolchain %s, go.mod minimum %s)",
				c.Product.ReleaseGoVersion, c.Product.GoVersion, c.Product.GoModDirective))
		} else {
			c.EvidenceGraph.AddLimitation(fmt.Sprintf(
				"stdlib advisory: applicability depends on the toolchain that built the release binary; pass --release-go-version or --binary (analysis toolchain %s, go.mod minimum %s)",
				c.Product.GoVersion, c.Product.GoModDirective))
		}
	}
	c.EvidenceGraph.ComputeHash()
	return workflow.Transition{Next: domain.StateEvaluateConditions, Reason: "deterministic evidence collection complete"}, nil
}

func (h CollectEvidence) runGovulncheck(ctx context.Context, c *domain.AnalysisCase) {
	// The DB snapshot identity doubles as the tool's version for the
	// audit trail and explains a not-covered advisory.
	var toolVer string
	if informer, ok := h.Govulncheck.(goanalysis.DBInformer); ok {
		if info, err := informer.DBInfo(ctx); err == nil {
			toolVer = info
		}
	}
	raw, err := h.Govulncheck.RunGovulncheck(ctx, c.Product.Repository, c.Product)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("govulncheck failed: %v", err))
		return
	}
	evID := c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:        domain.EvidenceGovulncheck,
		Quality:     domain.QualityDeterministic,
		Source:      "govulncheck -json -mode source ./...",
		Tool:        "govulncheck",
		ToolVersion: toolVer,
		Command:     "govulncheck -json -mode source ./...",
		Content:     string(raw),
	})
	res, err := goanalysis.Parse(raw)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(err.Error())
		return
	}
	covered := res.Covers(c.Vulnerability)
	if !covered && c.Vulnerability.Module != "" {
		covered = dbKnowsAdvisory(ctx, h.OSVBase, c.Vulnerability)
	}
	if covered {
		c.GovulncheckCoverage = "covered"
	} else {
		c.GovulncheckCoverage = "not_in_db"
		lim := "govulncheck emitted no findings referencing this advisory; reachability was not evaluated (silence is not evidence of no path)"
		if toolVer != "" {
			lim += fmt.Sprintf(" (local DB: %s; advisory modified: %s)", toolVer, orUnknown(c.Vulnerability.Modified))
		}
		c.EvidenceGraph.AddLimitation(lim)
	}
	for _, f := range res.ForVulnerability(c.Vulnerability) {
		cp := f.CallPath()
		cp.EvidenceID = evID
		c.EvidenceGraph.AddCallPath(cp)
	}
}

// isStdlibModule reports whether the module path is a Go standard library
// package (first path element has no dot — "net/http", "crypto/tls") or the
// toolchain pseudo-module.
func isStdlibModule(module string) bool {
	if module == "std" || module == "toolchain" || module == "cmd" {
		return true
	}
	first := module
	if i := strings.IndexByte(module, '/'); i >= 0 {
		first = module[:i]
	}
	return !strings.Contains(first, ".")
}

// runListenerScan records product functions that open network listeners or
// start servers. For server-side transport vulnerabilities this evidence lets
// conditions resolve input provenance as remote-peer-controlled.
func (h CollectEvidence) runListenerScan(ctx context.Context, c *domain.AnalysisCase) {
	lst, err := h.Source.FindListeners(ctx)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("listener scan failed: %v", err))
		return
	}
	if len(lst) == 0 {
		return
	}
	c.EvidenceGraph.AddEntrypoints(lst...)
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceEntrypoint,
		Quality: domain.QualityDeterministic,
		Source:  "source index: network listener scan",
		Tool:    "goanalysis.Index.FindListeners",
		Content: fmt.Sprintf("product opens %d network listener/server entrypoint(s)", len(lst)),
	})
}

// runExposure resolves network-exposure facts: inbound listener binds
// (ListenSites, with address arguments resolved through literals, consts,
// env vars and struct fields) and outbound endpoints into the vulnerable
// module (DialSites). env:/config:-sourced addresses are looked up in the
// repository's config files so a fact carries the concrete value when
// statically available. Facts are recorded unconditionally — evaluators
// distinguish "no exposure found" from "scan never ran" via the evidence
// record.
func (h CollectEvidence) runExposure(ctx context.Context, c *domain.AnalysisCase) {
	var facts []domain.ExposureFact
	in, err := h.Source.ListenSites(ctx)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("listener address scan failed: %v", err))
	} else {
		for i := range in {
			in[i].Scope = exposure.Scope(in[i].Address)
		}
		facts = append(facts, in...)
	}
	if module := c.Vulnerability.Module; module != "" && !isStdlibModule(module) {
		out, err := h.Source.DialSites(ctx, module)
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("dial-site scan failed: %v", err))
		} else {
			facts = append(facts, out...)
		}
	}
	if auth, err := h.Source.InboundAuthFacts(ctx); err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("inbound auth-middleware scan failed: %v", err))
	} else {
		facts = append(facts, auth...)
	}

	// Resolve env:/var:/field:-sourced addresses through the repo's config
	// files when a matching key exists.
	var items []exposure.Item
	if dir := c.Product.Repository; dir != "" {
		if scanned, err := exposure.ScanRepo(dir); err == nil {
			items = scanned
		} else {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("config scan failed: %v", err))
		}
	}
	for i := range facts {
		f := &facts[i]
		if f.Direction == "outbound" {
			f.Scope = exposure.OutboundScope(f.AddressSource)
		}
		if f.Address != "" || !strings.HasPrefix(f.AddressSource, "env:") {
			continue
		}
		if it := exposure.Lookup(items, strings.TrimPrefix(f.AddressSource, "env:")); it != nil {
			f.Address = it.Value
			f.AddressSource = fmt.Sprintf("env:%s (config %s:%d)", it.Key, filepathBase(it.File), it.Line)
			f.Scope = exposure.OutboundScope("config:" + it.Key)
		}
	}
	for _, f := range facts {
		c.EvidenceGraph.AddExposure(f)
	}
	var summary strings.Builder
	fmt.Fprintf(&summary, "%d exposure fact(s):", len(facts))
	for _, f := range facts {
		fmt.Fprintf(&summary, " %s %s", f.Direction, f.Target)
		if f.Address != "" {
			fmt.Fprintf(&summary, "=%s", f.Address)
		}
		if f.Scope != "" && f.Scope != domain.ScopeUnknown {
			fmt.Fprintf(&summary, "(%s)", f.Scope)
		}
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceConfiguration,
		Quality: domain.QualityDeterministic,
		Source:  "source index + repo config scan: exposure",
		Tool:    "goanalysis.Index.ListenSites+DialSites+InboundAuthFacts, exposure.ScanRepo",
		Content: summary.String(),
	})
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// runModuleUsage records product call sites into the vulnerable module's API.
// For library-internal sinks (unexported, peer-driven) module usage — not a
// direct symbol reference — is what makes the vulnerable code run.
func (h CollectEvidence) runModuleUsage(ctx context.Context, c *domain.AnalysisCase) {
	module := c.Vulnerability.Module
	if module == "" || isStdlibModule(module) {
		return
	}
	sites, err := h.Source.ModuleUsage(ctx, module)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("module usage scan failed: %v", err))
		return
	}
	// The check record is written even with zero sites: it distinguishes
	// "verified no usage" from "never attempted" for evaluators.
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "source index: module usage check",
		Tool:    "goanalysis.Index.ModuleUsage",
		Content: fmt.Sprintf("%d product call site(s) into module %s", len(sites), module),
	})
	if len(sites) == 0 {
		return
	}
	c.EvidenceGraph.AddModuleUsages(sites...)
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "source index: module usage",
		Tool:    "goanalysis.Index.ModuleUsage",
		Content: fmt.Sprintf("product calls into %s at %d site(s), e.g. %s.%s (%s:%d)",
			module, len(sites), sites[0].Package, sites[0].Function, sites[0].File, sites[0].Line),
	})

	// For affected symbols not invoked directly, trace call edges inside the
	// vendored module: product-used API → ... → sink.
	entries := map[string]bool{}
	for _, s := range sites {
		if s.Callee != "" {
			entries[s.Callee] = true
		}
	}
	var subjects []domain.SymbolRef
	for _, sym := range c.Vulnerability.AffectedSymbols {
		if strings.HasPrefix(sym.Package, module) {
			subjects = append(subjects, sym)
		}
	}
	if c.RootCause != nil {
		for _, rc := range c.RootCause.RootCauses {
			if strings.HasPrefix(rc.Package, module) {
				subjects = append(subjects, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
			}
		}
	}
	var entryList []string
	for e := range entries {
		entryList = append(entryList, e)
	}
	if len(subjects) == 0 || len(entryList) == 0 {
		return
	}
	reach, err := h.Source.ModuleInternalReach(ctx, module, entryList, subjects)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("module internal reach scan failed: %v", err))
		return
	}
	// Record the check itself: its presence distinguishes "verified no chain"
	// from "never attempted" for evaluators.
	checked := make([]string, 0, len(subjects))
	for _, s := range subjects {
		checked = append(checked, s.Package+"."+s.Symbol)
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "source index: module-internal reachability check",
		Tool:    "goanalysis.Index.ModuleInternalReach",
		Content: fmt.Sprintf("checked %d subject(s) against %d product-used API entr(ies): %s",
			len(subjects), len(entryList), strings.Join(checked, ", ")),
	})
	for key, chain := range reach {
		c.EvidenceGraph.AddModuleReachable(key, chain)
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSourceSnippet,
			Quality: domain.QualityDeterministic,
			Source:  "source index: module-internal call chain",
			Tool:    "goanalysis.Index.ModuleInternalReach",
			Content: fmt.Sprintf("%s reached from product-used API via: %s", key, strings.Join(chain, " -> ")),
		})
	}
}

// runSourceAnalysis gathers call sites, argument provenance and validations
// for conditions that carry a subject symbol.
func (h CollectEvidence) runSourceAnalysis(ctx context.Context, c *domain.AnalysisCase) {
	if c.Exploit == nil {
		return
	}
	if err := h.Source.Loaded(ctx); err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("source index load failed: %v", err))
		return
	}
	conds := append([]domain.Condition{}, c.Exploit.MandatoryConditions...)
	conds = append(conds, c.Exploit.SupportingFactors...)
	seen := map[domain.ConditionID]bool{}
	for _, cond := range conds {
		if seen[cond.ID] {
			continue
		}
		seen[cond.ID] = true
		subjects := cond.Subjects
		if cond.Subject != nil {
			subjects = append(append([]domain.SymbolRef{}, subjects...), *cond.Subject)
		}
		switch {
		case cond.Params[domain.ParamCheck] == domain.CheckSymbolPresent:
			h.collectPresence(ctx, c, dedupSubjects(subjects))
		case cond.Params[domain.ParamCheck] == domain.CheckConfigFlag:
			h.collectConfigFlag(ctx, c, cond)
		case cond.Params[domain.ParamCheck] == domain.CheckConfigKey:
			h.collectConfigKey(ctx, c, cond)
		case cond.Params[domain.ParamDirection] == domain.DirectionRead:
			h.collectReaders(ctx, c, dedupSubjects(subjects))
		case needsProvenance(cond.Kind):
			for _, subj := range dedupSubjects(subjects) {
				h.collectProvenance(ctx, c, cond, subj)
			}
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
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("find_callers %s.%s: %v", subj.Package, subj.Symbol, err))
		return
	}
	if len(sites) == 0 {
		c.EvidenceGraph.AddLimitation(
			fmt.Sprintf("no call sites of %s.%s found in product packages", subj.Package, subj.Symbol))
		return
	}
	for _, site := range sites {
		flows, evs, err := h.traceArgs(ctx, site, cond)
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("trace_argument %s:%d: %v", site.File, site.Line, err))
			continue
		}
		for _, flow := range flows {
			flow.ConditionID = cond.ID
			c.EvidenceGraph.AddDataFlows(flow)
		}
		for _, e := range evs {
			c.EvidenceGraph.AddEvidence(e)
		}
		// Unpinned input position scans every argument; a pinned one
		// scans just that arg — records carry the Arg index either way.
		var vals []domain.Validation
		var vev []domain.Evidence
		var verr error
		if cond.ArgIndex < 0 {
			vals, vev, verr = h.Source.FindAllValidations(ctx, site)
		} else {
			vals, vev, verr = h.Source.FindValidations(ctx, site, cond.ArgIndex)
		}
		err = verr
		if err == nil {
			for _, v := range vals {
				v.Property = fmt.Sprintf("cond=%s %s", cond.ID, v.Property)
				c.EvidenceGraph.AddValidations(v)
			}
			for _, e := range vev {
				c.EvidenceGraph.AddEvidence(e)
			}
		}
	}
}

// collectPresence resolves each subject in the dependency source for
// check=symbol_present conditions (INFO_LEAK pattern). Outcomes land in
// EvidenceGraph.SymbolDecls; the per-subject evidence record is written
// even on failure so evaluators can tell "checked" from "never ran".
func (h CollectEvidence) collectPresence(ctx context.Context, c *domain.AnalysisCase, subjects []domain.SymbolRef) {
	for _, subj := range subjects {
		key := subj.Package + "." + subj.Symbol
		site, err := h.Source.FindSymbol(ctx, subj)
		var content string
		switch {
		case err == nil:
			c.EvidenceGraph.AddSymbolDecl(key, site)
			content = fmt.Sprintf("%s declared at %s:%d", key, site.File, site.Line)
		case strings.Contains(err.Error(), "not found"):
			c.EvidenceGraph.AddSymbolDecl(key, nil)
			content = key + " not found in loaded packages"
		default:
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("presence check %s: %v", key, err))
			content = fmt.Sprintf("presence lookup for %s failed: %v", key, err)
		}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSearchResult,
			Quality: domain.QualityDeterministic,
			Source:  "presence check " + key,
			Tool:    "goanalysis.Index.FindSymbol",
			Content: content,
		})
	}
}

// collectReaders gathers product-code references to each subject for
// direction=read conditions (INFO_LEAK pattern): any reference is a
// candidate reader of the exposed datum. Sites land in
// EvidenceGraph.SymbolRefs; the per-subject check record is written even
// with zero hits to distinguish "verified none" from "never scanned".
func (h CollectEvidence) collectReaders(ctx context.Context, c *domain.AnalysisCase, subjects []domain.SymbolRef) {
	for _, subj := range subjects {
		key := subj.Package + "." + subj.Symbol
		sites, err := h.Source.SearchSymbol(ctx, subj)
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("read-scope check %s: %v", key, err))
			continue
		}
		if len(sites) > 0 {
			c.EvidenceGraph.AddSymbolRefs(key, sites...)
		}
		c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSearchResult,
			Quality: domain.QualityDeterministic,
			Source:  "read-scope check " + key,
			Tool:    "goanalysis.Index.SearchSymbol",
			Content: fmt.Sprintf("%d product reference site(s) to %s", len(sites), key),
		})
	}
}

// collectConfigFlag resolves a code-level configuration knob
// (config_package + config_symbol params): verifies the field exists in
// its package source, records the field kind (for Go zero-value
// reasoning) and collects every product assignment into
// EvidenceGraph.ConfigFlags.
func (h CollectEvidence) collectConfigFlag(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition) {
	pkg, sym := cond.Params[domain.ParamConfigPackage], cond.Params[domain.ParamConfigSymbol]
	if pkg == "" || sym == "" {
		return
	}
	key := pkg + "." + sym
	ref := domain.SymbolRef{Package: pkg, Symbol: sym}
	site, err := h.Source.FindSymbol(ctx, ref)
	var content string
	switch {
	case err == nil:
		c.EvidenceGraph.AddSymbolDecl(key, site)
		content = fmt.Sprintf("knob %s declared at %s:%d", key, site.File, site.Line)
	case strings.Contains(err.Error(), "not found"):
		c.EvidenceGraph.AddSymbolDecl(key, nil)
		content = "knob " + key + " not found in source"
	default:
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("config flag %s decl: %v", key, err))
		content = fmt.Sprintf("config flag lookup for %s failed: %v", key, err)
	}
	if kind, kerr := h.Source.SymbolFieldType(ctx, ref); kerr == nil && kind != "" {
		c.EvidenceGraph.AddConfigFieldKind(key, kind)
	}
	assigns, err := h.Source.FieldAssignments(ctx, ref)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("config flag %s assignments: %v", key, err))
		return
	}
	c.EvidenceGraph.AddConfigFlag(key, assigns...)
	content += fmt.Sprintf("; %d assignment(s) in product code", len(assigns))
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSearchResult,
		Quality: domain.QualityDeterministic,
		Source:  "config flag check " + key,
		Tool:    "goanalysis.Index.FindSymbol+FieldAssignments",
		Content: content,
	})
}

// collectConfigKey resolves a file-level configuration knob
// (config_key param): scans repository config files for the key and
// records matches into EvidenceGraph.Configuration.
func (h CollectEvidence) collectConfigKey(_ context.Context, c *domain.AnalysisCase, cond domain.Condition) {
	key := cond.Params[domain.ParamConfigKey]
	if key == "" {
		return
	}
	dir := c.Product.Repository
	var content string
	if dir == "" {
		content = "repository path unavailable — config scan skipped"
	} else if items, err := exposure.FindKey(dir, key); err != nil {
		content = fmt.Sprintf("config key scan failed: %v", err)
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("config key %s: %v", key, err))
	} else {
		for _, it := range items {
			evID := c.EvidenceGraph.AddEvidence(domain.Evidence{
				Kind:    domain.EvidenceConfiguration,
				Quality: domain.QualityDeterministic,
				Source:  "config file " + it.File,
				Tool:    "exposure.FindKey",
				Content: fmt.Sprintf("%s=%s", it.Key, it.Value),
			})
			c.EvidenceGraph.AddConfigItem(domain.ConfigItem{
				Key: it.Key, Value: it.Value, File: it.File, Line: it.Line, Evidence: evID,
			})
		}
		content = fmt.Sprintf("%d occurrence(s) of key %q in repo config files", len(items), key)
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSearchResult,
		Quality: domain.QualityDeterministic,
		Source:  "config key check " + key,
		Tool:    "exposure.FindKey",
		Content: content,
	})
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
	var pending []domain.Condition
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
		} else if claim.Result == domain.ClaimUnknown {
			pending = append(pending, cond)
		}
		c.Claims = append(c.Claims, claim)
	}
	// The fallback (LLM agent) runs only on UNKNOWN conditions and only
	// when no mandatory condition is already FALSE: a proven-false
	// condition caps the verdict below EXPLOITABLE regardless of the rest,
	// so spending bounded-expensive agent steps cannot change the outcome.
	if !hasFalse {
		// Conditions are independent: run the fallback concurrently.
		// EvidenceGraph and Usage counters are mutex-guarded.
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, cond := range pending {
			if h.Fallback == nil || !h.Fallback.CanEvaluate(cond) {
				continue
			}
			wg.Add(1)
			go func(cond domain.Condition) {
				defer wg.Done()
				alt := h.Fallback.Evaluate(cond, c)
				mu.Lock()
				defer mu.Unlock()
				claim := findClaim(c.Claims, cond.ID)
				if claim == nil {
					return
				}
				if alt.Result != domain.ClaimUnknown || len(alt.EvidenceIDs) > 0 {
					*claim = alt
				}
				if claim.Result == domain.ClaimFalse {
					hasFalse = true
				}
			}(cond)
		}
		wg.Wait()
	} else {
		c.EvidenceGraph.AddLimitation(
			"agent fallback skipped: a mandatory condition is already FALSE, so remaining UNKNOWNs cannot change the verdict")
	}
	// Supporting factors never gate the verdict, but they still get
	// claims — exposure/priority facts belong in the report, not only in
	// the raw evidence graph.
	for _, cond := range c.Exploit.SupportingFactors {
		if existing[cond.ID] {
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
		c.Claims = append(c.Claims, claim)
	}
	if hasFalse {
		return workflow.Transition{Next: domain.StateNegativeCheck, Reason: "candidate FALSE requires negative verification"}, nil
	}
	if allMandatoryTrue(c) {
		return workflow.Transition{Next: domain.StateReview, Reason: "all mandatory conditions satisfied"}, nil
	}
	return workflow.Transition{Next: domain.StateGapAnalysis, Reason: "unresolved mandatory conditions"}, nil
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
		c.EvidenceGraph.AddLimitation("reviewer not configured; proposed verdict not reviewed")
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review skipped: no reviewer"}, nil
	}
	maxIt := c.Workflow.Limits.MaxReviewIterations
	if maxIt <= 0 {
		maxIt = 2
	}
	if len(c.Reviews) >= maxIt {
		c.EvidenceGraph.AddLimitation("review iteration budget exhausted; verdict computed on repaired claims")
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review budget exhausted"}, nil
	}

	// The proposed verdict is computed deterministically before review;
	// the reviewer may only repair claims, never set the verdict.
	proposed := h.Evaluator.Evaluate(affectedOf(c), exploitOf(c), c.Claims)
	rev := h.Reviewer.Review(c, proposed)
	rev.ID = domain.ReviewID(fmt.Sprintf("REV-%d", len(c.Reviews)+1))
	c.Reviews = append(c.Reviews, rev)
	c.IncReviewIterations()
	c.EvidenceGraph.ComputeHash()

	if rev.Result != domain.ReviewRevise {
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "review ACCEPT"}, nil
	}
	// REVISE routes through the repair state; after bounded repair the case
	// re-enters REVIEW so the reviewer audits the repaired claim set.
	return workflow.Transition{Next: domain.StateRepairAnalysis, Reason: "review REVISE"}, nil
}

// RepairAnalysis applies the bounded repair for the latest review's
// findings: high-severity claim findings demote the claim to UNKNOWN.
// Repairs only remove unsupported strength — never add evidence or
// promote a claim. A repaired case goes back to REVIEW so the reviewer
// sees the repaired claim set; an unrepairable finding (model/verdict
// targets) falls through to the verdict.
type RepairAnalysis struct{}

func (RepairAnalysis) State() domain.WorkflowState { return domain.StateRepairAnalysis }

func (RepairAnalysis) Run(_ context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if len(c.Reviews) == 0 {
		return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: "repair without a review"}, nil
	}
	rev := c.Reviews[len(c.Reviews)-1]
	repaired := false
	for _, f := range rev.Findings {
		if f.TargetType != "claim" || f.Severity != "high" {
			continue
		}
		for i := range c.Claims {
			if string(c.Claims[i].ID) != f.TargetID || c.Claims[i].Result == domain.ClaimUnknown {
				continue
			}
			// A TRUE claim backed by deterministic evidence is verified fact —
			// a reviewer's reinterpretation cannot undo it; the concern is
			// recorded as a caveat instead. FALSE claims stay demotable:
			// negative verification is weaker by nature.
			if c.Claims[i].Result == domain.ClaimTrue &&
				strings.HasPrefix(c.Claims[i].Producer, "evaluator.") &&
				claimHasDeterministicEvidence(c, &c.Claims[i]) {
				c.Claims[i].Limitations = append(c.Claims[i].Limitations,
					"reviewer concern (claim kept: deterministic evidence): "+f.Problem)
				continue
			}
			c.Claims[i].Result = domain.ClaimUnknown
			c.Claims[i].Limitations = append(c.Claims[i].Limitations,
				"demoted by reviewer: "+f.Problem)
			repaired = true
		}
	}
	if !repaired {
		return workflow.Transition{Next: domain.StateEvaluateVerdict,
			Reason: "review REVISE: no repairable claims"}, nil
	}
	return workflow.Transition{Next: domain.StateReview,
		Reason: "repaired claims; re-review"}, nil
}

// claimHasDeterministicEvidence reports whether any evidence attached to the
// claim carries deterministic quality (tool output, not LLM inference).
func claimHasDeterministicEvidence(c *domain.AnalysisCase, cl *domain.Claim) bool {
	if len(cl.EvidenceIDs) == 0 {
		return false
	}
	byID := map[domain.EvidenceID]domain.EvidenceQuality{}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		byID[e.ID] = e.Quality
	}
	for _, id := range cl.EvidenceIDs {
		if q := byID[id]; q == domain.QualityDeterministic || q == domain.QualityAuthoritative {
			return true
		}
	}
	return false
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
	// Prior is the previous stored run of the same vuln/repo pair; when
	// set, its tool_executions hashes are diffed against this run's.
	Prior *domain.AnalysisCase
}

// diffToolExecutions records the reproducibility-diff between a prior
// run's audit trail and this one as RUNTIME evidence — drift means the
// deterministic layer produced different outputs across runs.
func diffToolExecutions(c, prior *domain.AnalysisCase) {
	drift := toolaudit.DiffExecutions(prior.EvidenceGraph.ToolExecutions, c.EvidenceGraph.ToolExecutions)
	content := fmt.Sprintf("baseline=%s invocations: prior=%d current=%d drift=%d",
		prior.ID, len(prior.EvidenceGraph.ToolExecutions), len(c.EvidenceGraph.ToolExecutions), len(drift))
	if len(drift) > 0 {
		content += "\n" + strings.Join(drift, "\n")
	}
	c.EvidenceGraph.AddRuntimeEvidence(domain.Evidence{
		Quality: domain.QualityDeterministic,
		Source:  "reproducibility-diff",
		Content: content,
	})
	if len(drift) > 0 {
		c.EvidenceGraph.AddLimitation(fmt.Sprintf(
			"reproducibility: %d tool invocation(s) drifted vs prior run %s", len(drift), prior.ID))
	}
}

func (BuildReport) State() domain.WorkflowState { return domain.StateBuildReport }

func (h BuildReport) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.Prior != nil {
		diffToolExecutions(c, h.Prior)
	}
	if err := report.Write(h.Dir, c); err != nil {
		return workflow.Transition{}, fmt.Errorf("build report: %w", err)
	}
	if h.Tracker != nil {
		if err := h.Tracker.Publish(ctx, string(c.ID), report.Markdown(c)); err != nil {
			c.EvidenceGraph.AddToolLimitation("tracker publish failed: " + err.Error())
		}
	}
	return workflow.Transition{Next: domain.StateCompleted, Reason: "report written to " + h.Dir}, nil
}

// dbKnowsAdvisory reports whether the Go vulnerability database (mirrored by
// the OSV API) holds a GO-* record matching the vulnerability or its aliases.
// Only GO-* entries count: govulncheck's DB contains Go-ecosystem records; a
// bare GHSA/OSV document does not imply coverage.
func dbKnowsAdvisory(ctx context.Context, base string, v domain.Vulnerability) bool {
	refs, err := vulnerability.QueryOSVRefs(ctx, base, v.Module)
	if err != nil {
		return false
	}
	want := map[string]bool{v.ID: true}
	for _, a := range v.Aliases {
		want[a] = true
	}
	for _, r := range refs {
		if !strings.HasPrefix(r.ID, "GO-") {
			continue
		}
		if want[r.ID] {
			return true
		}
		for _, a := range r.Aliases {
			if want[a] {
				return true
			}
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}
