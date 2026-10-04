package goanalysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Verifier performs a bounded negative verification pass on FALSE claims.
// It searches for alternate references, dynamic escapes and provenance
// bypasses that static analysis may have missed. A FALSE claim only survives
// when the falsification pass finds no counterexample within the searchable
// scope; contradictions demote it back to UNKNOWN.
// verifyHops bounds the re-trace budget negative verification uses when
// re-deriving argument origins — the same budget gap analysis applies,
// so a claim resolved by a deep trace is not re-judged on a shallow one.
const verifyHops = 16

type Verifier struct {
	Source *Index
}

// VerifyFalse attempts to falsify a FALSE claim for cond across all of its
// subjects and returns the updated claim with its NegativeVerification.
func (v Verifier) VerifyFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition) domain.Claim {

	if claim.Falsifier == domain.FalsifierLocusFunctionUnreached {
		out := v.verifyLocusFunctionUnreached(ctx, c, claim, cond)
		if out.NegativeVerification != nil &&
			out.NegativeVerification.Status == domain.NegativeVerified &&
			v.Source != nil {
			subjects := append([]domain.SymbolRef{}, cond.Subjects...)
			if cond.Subject != nil {
				subjects = append(subjects, *cond.Subject)
			}
			v.extendNegativeScope(ctx, c, out.NegativeVerification, subjects)
		}
		return out
	}

	// The locus falsifier is verified against the persisted build-graph
	// evidence, not the source index — it applies even when no index is
	// configured, and package absence cannot be escaped by any dispatch.
	if cond.Params[domain.ParamCheck] == domain.CheckLocus {
		return v.verifyLocusAbsent(c, claim, cond)
	}

	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	if v.Source == nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "source index not configured",
		})
	}
	subjects := append([]domain.SymbolRef{}, cond.Subjects...)
	if cond.Subject != nil {
		subjects = append(subjects, *cond.Subject)
	}
	if len(subjects) == 0 && c.Exploit != nil {
		subjects = append(subjects, c.Exploit.RootCauses...)
	}
	if len(subjects) == 0 && c.RootCause != nil {
		for _, rc := range c.RootCause.RootCauses {
			subjects = append(subjects, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
		}
	}
	if len(subjects) == 0 {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "no subject symbols on condition",
		})
	}

	// Parametric checks (config knobs, exposure, symbol presence) are
	// falsified by their own evidence, not by subject-escape rules — the
	// subjects bound to such conditions are advisory sinks, and a
	// func_value marker on a sink says nothing about the knob's value.
	switch cond.Params[domain.ParamCheck] {
	case domain.CheckConfigFlag, domain.CheckConfigKey,
		domain.CheckExposure, domain.CheckSymbolPresent:
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "parametric check condition — subject-escape falsification does not apply",
		})
	}

	if claim.Falsifier == domain.FalsifierTrustedInfrastructure && c != nil && c.Product.TrustedPeer {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeVerified,
			Notes:  "FALSE is decided by product snapshot deployment trust facts (--trusted-peer)",
		})
	}

	allSites := map[string][]domain.CallSite{}
	anyExported := false
	for _, s := range subjects {
		if symbolExported(s) {
			anyExported = true
		}
	}
	dynSeen := map[string]bool{}
	var strayLinkname int
	for _, subj := range subjects {
		sites, err := v.Source.SearchSymbol(ctx, subj)
		if err != nil {
			return setNeg(claim, &domain.NegativeVerification{
				Status: domain.NegativeInsufficientScope,
				Notes:  "symbol search failed: " + err.Error(),
			})
		}
		allSites[subj.Package+"."+subj.Symbol] = sites

		markers, err := v.Source.ScanDynamic(ctx, subj)
		if err != nil {
			return setNeg(claim, &domain.NegativeVerification{
				Status: domain.NegativeInsufficientScope,
				Notes:  "dynamic scan failed: " + err.Error(),
			})
		}
		for _, m := range markers {
			evID := c.EvidenceGraph.AddEvidence(domain.Evidence{
				Kind:    domain.EvidenceSourceSnippet,
				Quality: domain.QualityDeterministic,
				Source:  "go-analysis ScanDynamic",
				Tool:    "goanalysis.Index",
				Content: fmt.Sprintf("%s at %s:%d: %s", m.Kind, m.File, m.Line, m.Detail),
			})
			nv.EvidenceIDs = append(nv.EvidenceIDs, evID)
			switch m.Kind {
			case "func_value":
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("symbol %s escapes static call graph via %s at %s:%d",
					subj.Package+"."+subj.Symbol, m.Kind, m.File, m.Line)
				return setNeg(claim, nv)
			case "linkname":
				// go:linkname contradicts only when it targets this symbol —
				// an unrelated pragma cannot invoke it.
				if strings.Contains(m.Detail, subj.Package) || linknameNames(m.Detail, subj) {
					nv.Status = domain.NegativeContradicted
					nv.Notes = fmt.Sprintf("symbol %s escapes static call graph via go:linkname at %s:%d",
						subj.Package+"."+subj.Symbol, m.File, m.Line)
					return setNeg(claim, nv)
				}
				strayLinkname++
			case "reflect":
				// Bare reflect import does not invoke functions or widen call graphs;
				// only reflect_method markers (MethodByName / Method) do.
				continue
			case "reflect_method":
				// Dynamic method dispatch via reflect (MethodByName / Method).
				// In Go, package-level standalone functions cannot be invoked
				// dynamically via reflect by name — Go reflection has no package
				// registry. Only exported methods on struct/interface types
				// can be dispatched dynamically.
				if claim.Falsifier == domain.FalsifierGuards {
					continue
				}
				if !symbolIsMethod(subj) || !symbolExported(subj) {
					continue
				}
				if v.Source != nil && !v.Source.IsReceiverTypeInstantiated(subj) {
					continue
				}
				if !dynSeen[m.Kind] {
					dynSeen[m.Kind] = true
					nv.Limitations = append(nv.Limitations,
						"reflect method dispatch usage in product widens the call graph; static negative verification is weaker")
				}
			case "unsafe":
				// Bare unsafe import does not invoke functions or widen call graphs;
				// unsafe_write / unsafe_ptr markers handle pointer mutations.
				continue
			case "plugin":
				// Go plugin.Open + Lookup can look up any exported symbol (function or var).
				if anyExported && !dynSeen[m.Kind] {
					dynSeen[m.Kind] = true
					nv.Limitations = append(nv.Limitations,
						m.Kind+" usage in product widens the call graph; static negative verification is weaker")
				}
			case "reflect_write":
				// A Set* call can mutate a guarded field out of sight of
				// syntactic write-site scans — but reflect.Set works only on
				// *exported* fields; when every covered field is unexported
				// this marker cannot invalidate the coverage.
				if claim.Falsifier == domain.FalsifierGuards && !hasExportedCoveredField(c, claim) {
					continue
				}
				if !dynSeen[m.Kind] {
					dynSeen[m.Kind] = true
					nv.Limitations = append(nv.Limitations,
						"reflect.Value.Set* call at "+m.File+":"+fmt.Sprint(m.Line)+
							" can write fields invisibly; guard coverage is weaker")
				}
			case "unsafe_write", "unsafe_ptr":
				// A store through an unsafe.Pointer-derived value — or a
				// materialized raw pointer whose aliased writes cannot be
				// traced — can write *any* field, including unexported ones,
				// so it weakens guard coverage unconditionally.
				if !dynSeen[m.Kind] {
					dynSeen[m.Kind] = true
					nv.Limitations = append(nv.Limitations,
						m.Detail+" at "+m.File+":"+fmt.Sprint(m.Line)+
							"; guard coverage is weaker")
				}
			}
		}
	}
	if strayLinkname > 0 {
		nv.Notes += fmt.Sprintf(" %d unrelated go:linkname pragma(s) ignored", strayLinkname)
	}

	var out domain.Claim
	switch {
	case cond.Kind == domain.ConditionSymbolReachable &&
		cond.Params[domain.ParamDirection] == domain.DirectionRead:
		out = v.verifyReadFalse(claim, nv, subjects, allSites)
	case cond.Kind == domain.ConditionSymbolReachable &&
		cond.Params[domain.ParamSequence] != "":
		out = v.verifySequenceFalse(c, claim, nv, subjects, allSites)
	default:
		switch cond.Kind {
		case domain.ConditionSymbolReachable:
			out = v.verifyReachableFalse(ctx, c, claim, nv, subjects, allSites)
		case domain.ConditionAttackerControl:
			out = v.verifyInputFalse(ctx, c, claim, nv, subjects, cond.ArgIndex)
		case domain.ConditionInputConstraint:
			if claim.Falsifier == domain.FalsifierGuards {
				out = v.verifyGuardFalse(ctx, c, claim, nv)
			} else {
				out = v.verifyInputFalse(ctx, c, claim, nv, subjects, cond.ArgIndex)
			}
		case domain.ConditionValidation:
			out = v.verifyGuardFalse(ctx, c, claim, nv)
		case domain.ConditionPlatform, domain.ConditionRuntime:
			out = verifySnapshotFalse(claim, nv)
		default:
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "no falsification strategy for condition kind " + string(cond.Kind)
			out = setNeg(claim, nv)
		}
	}
	// A VERIFIED negative is scoped to what the loaded index can see:
	// extend the scope to build-tag-excluded files and interface
	// dispatch before letting a verdict rely on it.
	if out.NegativeVerification != nil &&
		out.NegativeVerification.Status == domain.NegativeVerified {
		v.extendNegativeScope(ctx, c, out.NegativeVerification, subjects)
	}
	return out
}

// extendNegativeScope widens the negative check beyond the typed index:
// references in files excluded by the current build tags, and call sites
// where the subject's method could be reached through interface
// dispatch. Either finding downgrades VERIFIED to INSUFFICIENT_SCOPE —
// they show an un-closed scope, not a proven path, so the claim's FALSE
// result is kept but cannot support the verdict.
func (v Verifier) extendNegativeScope(ctx context.Context, c *domain.AnalysisCase,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef) {

	addSites := func(tool string, sites []domain.CallSite) {
		for _, s := range sites {
			nv.EvidenceIDs = append(nv.EvidenceIDs, c.EvidenceGraph.AddEvidence(domain.Evidence{
				Kind:    domain.EvidenceSourceSnippet,
				Quality: domain.QualityDeterministic,
				Source:  "go-analysis " + tool,
				Tool:    "goanalysis.Index",
				Content: fmt.Sprintf("%s.%s referenced at %s:%d", s.Package, s.Function, s.File, s.Line),
			}))
		}
	}
	for _, subj := range subjects {
		gated, err := v.Source.GatedRefs(ctx, subj)
		if err != nil {
			nv.Limitations = append(nv.Limitations, "build-tag-excluded scan failed: "+err.Error())
			continue
		}
		if len(gated) > 0 {
			addSites("GatedRefs", gated)
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes += fmt.Sprintf(" %d reference(s) to %s.%s in files excluded by the current build tags — an alternate build configuration may reach the subject;",
				len(gated), subj.Package, subj.Symbol)
		}
		disp, err := v.Source.InterfaceDispatchSites(ctx, subj)
		if err != nil {
			nv.Limitations = append(nv.Limitations, "interface dispatch scan failed: "+err.Error())
			continue
		}
		if len(disp) > 0 {
			addSites("InterfaceDispatchSites", disp)
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes += fmt.Sprintf(" %d interface-dispatched call site(s) may invoke %s.%s — the concrete implementation behind an interface is not resolved;",
				len(disp), subj.Package, subj.Symbol)
		}
	}
}

// verifyReadFalse falsifies a direction=read FALSE ("no product reader of
// the exposed datum"): any static product reference to a subject IS a
// reader candidate, so it contradicts the FALSE outright rather than
// merely weakening it.
func (v Verifier) verifyReadFalse(claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef,
	allSites map[string][]domain.CallSite) domain.Claim {

	if hidden := unreferenceable(subjects); len(hidden) > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = fmt.Sprintf("subject(s) %s are internal/unexported — the product cannot reference "+
			"them at all, so zero product references is forced by visibility, not by absent reads",
			strings.Join(hidden, ", "))
		return setNeg(claim, nv)
	}
	var total int
	for _, s := range subjects {
		total += len(allSites[s.Package+"."+s.Symbol])
	}
	if total == 0 {
		nv.Notes = fmt.Sprintf("none of %d subject(s) is referenced in product code",
			len(subjects))
		return setNeg(claim, nv)
	}
	nv.Status = domain.NegativeContradicted
	nv.Notes = fmt.Sprintf("%d product reference(s) to the subject(s) exist — reader candidates the FALSE did not see",
		total)
	return setNeg(claim, nv)
}

// verifySequenceFalse falsifies a sequence FALSE ("the round-trip pair is
// incomplete"). Only the never-invoked members can resurrect it: if the
// product still statically references them, an indirect invocation path
// cannot be excluded.
func (v Verifier) verifySequenceFalse(c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef,
	allSites map[string][]domain.CallSite) domain.Claim {

	var missing []string
	for _, s := range subjects {
		key := s.Package + "." + s.Symbol
		if _, ok := c.EvidenceGraph.ModuleReachable[key]; ok {
			continue
		}
		called := false
		for _, u := range c.EvidenceGraph.ModuleUsages {
			if u.Callee == key {
				called = true
				break
			}
		}
		if !called {
			missing = append(missing, key)
		}
	}
	refs := 0
	var missingRefs []domain.SymbolRef
	for _, m := range missing {
		refs += len(allSites[m])
		for _, s := range subjects {
			if s.Package+"."+s.Symbol == m {
				missingRefs = append(missingRefs, s)
			}
		}
	}
	if hidden := unreferenceable(missingRefs); len(hidden) > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = fmt.Sprintf("never-invoked member(s) %s are internal/unexported — the product cannot "+
			"reference them at all, so zero product references cannot exclude dep-internal invocation",
			strings.Join(hidden, ", "))
		return setNeg(claim, nv)
	}
	if refs == 0 {
		nv.Notes = fmt.Sprintf("never-invoked member(s) %s have no product references",
			strings.Join(missing, ", "))
		return setNeg(claim, nv)
	}
	nv.Status = domain.NegativeInsufficientScope
	nv.Notes = fmt.Sprintf("%d product reference(s) to never-invoked member(s) exist; "+
		"cannot exclude indirect invocation", refs)
	return setNeg(claim, nv)
}

// verifyReachableFalse: govulncheck reported no call path. A FALSE survives
// only when no subject has references at all; any static reference without
// a call path could still execute via an un-modeled entrypoint or dispatch.
// Subjects the product cannot legally name (internal packages, unexported
// identifiers or receiver types) contribute nothing: zero references to
// them is forced by Go visibility rules, and dep-internal dispatch paths
// (filter registries, watcher callbacks) stay invisible to a product-ref
// scan — treat them as un-closed scope, not as falsifier evidence.
func (v Verifier) verifyReachableFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef,
	allSites map[string][]domain.CallSite) domain.Claim {

	if claim.Falsifier == domain.FalsifierConfigGatedOff {
		nv.Status = domain.NegativeVerified
		nv.Notes = "all call paths and references to affected symbol(s) are guarded by statically disabled configuration (dead code)"
		return setNeg(claim, nv)
	}

	if hidden := unreferenceable(subjects); len(hidden) > 0 {
		// When the falsifier is govulncheck-silence, govulncheck's whole-program
		// call graph trace explicitly covers unexported functions too. If the
		// dependency invocation check confirms that no dep-internal caller
		// chain is live, the unexported subject cannot execute via dep-internal
		// dispatch either.
		if claim.Falsifier != domain.FalsifierGovulncheckSilence {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = fmt.Sprintf("subject(s) %s are internal/unexported — the product cannot reference "+
				"them at all, so zero product references is forced by visibility and cannot exclude "+
				"dep-internal dispatch", strings.Join(hidden, ", "))
			return setNeg(claim, nv)
		}
	}
	total := 0
	for _, s := range subjects {
		total += len(allSites[s.Package+"."+s.Symbol])
	}
	if total == 0 {
		// Zero product references proves only that the product never
		// names the subject — not that it is unreached. Dep-internal
		// call sites are outside that scope; a member dead in the whole
		// build while its receiver pipeline runs is a missing-call
		// shape, where the absent call IS the vulnerable behavior.
		if weak := v.checkDepInvocation(ctx, c, subjects); weak != "" {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = weak
			return setNeg(claim, nv)
		}
		nv.Notes = fmt.Sprintf("none of %d affected symbol(s) is referenced in product code",
			len(subjects))
		return setNeg(claim, nv)
	}
	nv.Status = domain.NegativeInsufficientScope
	nv.Notes = fmt.Sprintf("%d static reference(s) across %d subject(s) exist without a govulncheck path; "+
		"cannot exclude dynamic dispatch or un-modeled entrypoints", total, len(subjects))
	return setNeg(claim, nv)
}

// checkDepInvocation widens a zero-product-references result to the
// dependency's own call graph. Two findings weaken the falsifier:
// dep-internal call sites of the subject exist — invocation is live,
// just not product-driven — or the subject is a method dead in the whole
// build while sibling methods on the same receiver type run inside the
// dep. The second is the missing-call shape: the check member never
// executes while the validation pipeline around it does, which is
// precisely the vulnerable behavior for missing-validation advisories —
// so deadness cannot ground a negative verdict.
func (v Verifier) checkDepInvocation(ctx context.Context, c *domain.AnalysisCase, subjects []domain.SymbolRef) string {
	mods := caseModules(c)
	if len(mods) == 0 {
		return ""
	}
	for _, subj := range subjects {
		inScope := false
		for _, m := range mods {
			if subj.Package == m || strings.HasPrefix(subj.Package, m+"/") {
				inScope = true
				break
			}
		}
		if !inScope {
			continue
		}
		callers, siblingLive, unbounded, err := v.Source.DepInvocationState(ctx, subj)
		if err != nil {
			return fmt.Sprintf("dep invocation scan failed for %s.%s: %v", subj.Package, subj.Symbol, err)
		}
		if unbounded {
			return fmt.Sprintf("subject %s.%s is exported and other dependency modules import "+
				"its package — dep-internal callers are not enumerable, so zero product "+
				"references cannot exclude invocation", subj.Package, subj.Symbol)
		}
		if callers > 0 {
			return fmt.Sprintf("subject %s.%s has %d call site(s) inside the dependency — "+
				"zero product references cannot exclude dep-internal invocation",
				subj.Package, subj.Symbol, callers)
		}
		if siblingLive {
			return fmt.Sprintf("subject %s.%s is never invoked anywhere in the build, but sibling "+
				"methods on the same receiver type are invoked inside the dependency — a missing-call "+
				"shape: absence of the check is itself the vulnerable behavior, so a dead member "+
				"cannot ground a negative verdict", subj.Package, subj.Symbol)
		}
	}
	return ""
}

// caseModules returns every dependency module the case resolved against:
// Affected.SelectedModules carries each linked affected entry of a
// multi-module advisory; for single-module intakes (and unit tests that
// set only the flat field) it falls back to Vulnerability.Module. A
// subject's module membership decides whether its dep-internal callers
// are in scope for the negative check — a symbol unioned from a second
// linked module must not be skipped.
func caseModules(c *domain.AnalysisCase) []string {
	if c == nil {
		return nil
	}
	if c.Affected != nil && len(c.Affected.SelectedModules) > 0 {
		return c.Affected.SelectedModules
	}
	if c.Vulnerability.Module != "" {
		return []string{c.Vulnerability.Module}
	}
	return nil
}

// inCaseModules reports whether pkgPath belongs to any of the modules —
// the module root package itself or any subpackage.
func inCaseModules(pkgPath string, mods []string) bool {
	for _, m := range mods {
		if domain.PackageInModule(pkgPath, m) {
			return true
		}
	}
	return false
}

// verifyInputFalse verifies the FALSE candidate for ATTACKER_CONTROL /
// INPUT_CONSTRAINT: every call site of every subject must pass arguments
// whose provenance resolves to a non-external origin (argIndex < 0 covers
// all arguments).
func (v Verifier) verifyInputFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef, argIndex int) domain.Claim {

	totalCallers := 0
	absorbed := 0
	mods := caseModules(c)
	for _, subj := range subjects {
		callers, err := v.Source.FindCallers(ctx, subj)
		if err != nil {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "caller search failed: " + err.Error()
			return setNeg(claim, nv)
		}
		if len(callers) == 0 && inCaseModules(subj.Package, mods) &&
			claim.Falsifier != domain.FalsifierConstantOrGeneratedInput &&
			claim.Falsifier != domain.FalsifierTrustedInfrastructure {
			// Unexported dependency subjects have no product callers — the
			// FALSE under verification may have been produced by dep-internal
			// provenance; re-trace the same dep scope. Membership is checked
			// against every linked module — a second-module subject must not
			// be skipped by a single-module prefix test.
			depCallers, derr := v.Source.FindDepCallers(ctx, subj)
			if derr != nil {
				nv.Status = domain.NegativeInsufficientScope
				nv.Notes = "dep caller search failed: " + derr.Error()
				return setNeg(claim, nv)
			}
			callers = depCallers
		}
		if len(callers) == 0 {
			continue // no direct call sites of this subject; others may still contradict
		}
		totalCallers += len(callers)
		for _, site := range callers {
			var flows []domain.DataFlow
			var evs []domain.Evidence
			var err error
			if argIndex < 0 {
				flows, evs, err = v.Source.TraceAllArgumentsBound(ctx, site, verifyHops)
			} else {
				var f domain.DataFlow
				f, evs, err = v.Source.TraceArgumentBound(ctx, site, argIndex, verifyHops)
				flows = []domain.DataFlow{f}
			}
			if err != nil {
				nv.Status = domain.NegativeInsufficientScope
				nv.Notes = "provenance failed at " + site.Function + ": " + err.Error()
				return setNeg(claim, nv)
			}
			for _, e := range evs {
				nv.EvidenceIDs = append(nv.EvidenceIDs, c.EvidenceGraph.AddEvidence(e))
			}
			for _, flow := range flows {
				switch inputOriginVerification(flow.Origin, claim.Falsifier) {
				case domain.NegativeContradicted:
					nv.Status = domain.NegativeContradicted
					nv.Notes = fmt.Sprintf("call site %s passes %s input (%s); FALSE contradicted",
						site.Function, flow.Origin, flow.Summary)
					return setNeg(claim, nv)
				case domain.NegativeInsufficientScope:
					// A sink inside the vulnerable module's cone passes a
					// dependency-internal value — its provenance is the
					// ingress closure's job, not call-site tracing. The
					// verifyIngress pass below must confirm the closure is
					// complete and all-reaching-safe, or it fails there.
					if c.Vulnerability.Module != "" &&
						domain.PackageInModule(site.Package, c.Vulnerability.Module) {
						absorbed++
						continue
					}
					// Absence of evidence is not a contradiction: the
					// verifier could not resolve this argument — scope
					// insufficient to confirm the FALSE, not disproven.
					nv.Status = domain.NegativeInsufficientScope
					nv.Notes = fmt.Sprintf("call site %s argument %d unresolvable (%s); cannot verify FALSE",
						site.Function, flow.Arg, flow.Summary)
					return setNeg(claim, nv)
				}
			}
		}
	}
	if totalCallers == 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "no direct call sites found for any subject; indirect invocation possible"
		return setNeg(claim, nv)
	}
	if claim.Falsifier == domain.FalsifierConstantOrGeneratedInput && totalCallers > 0 {
		nv.Status = domain.NegativeVerified
		nv.Notes = fmt.Sprintf("all %d call site(s) across %d subject(s) pass verified constant or generated payload",
			totalCallers, len(subjects))
		return setNeg(claim, nv)
	}
	if claim.Falsifier == domain.FalsifierTrustedInfrastructure && totalCallers > 0 {
		nv.Status = domain.NegativeVerified
		nv.Notes = fmt.Sprintf("all %d call site(s) across %d subject(s) consume local configuration files (trusted infrastructure)",
			totalCallers, len(subjects))
		return setNeg(claim, nv)
	}
	// A complete closure — either strategy the spec allows — discharges
	// the dep-internal arguments the per-site trace could not resolve.
	ingressNote := v.verifyIngress(ctx, c, claim.ConditionID, nv, subjects)
	if ingressNote == "" {
		nv.Notes = fmt.Sprintf("all %d call site(s) across %d subject(s) pass non-external input",
			totalCallers, len(subjects))
		if absorbed > 0 {
			nv.Notes += fmt.Sprintf("; %d dep-internal sink arg(s) absorbed by verified ingress closure", absorbed)
		}
		return setNeg(claim, nv)
	}
	if note := v.verifySinkClosure(ctx, c, claim, nv, subjects, argIndex); note == "" {
		nv.Status = domain.NegativeVerified
		nv.Notes = fmt.Sprintf("all %d call site(s) across %d subject(s) pass non-external input",
			totalCallers, len(subjects))
		if absorbed > 0 {
			nv.Notes += fmt.Sprintf("; %d dep-internal sink arg(s) absorbed by verified sink closure", absorbed)
		}
		nv.Notes += "; ingress closure could not verify: " + ingressNote
		return setNeg(claim, nv)
	}
	return setNeg(claim, nv)
}

// verifySinkClosure re-runs the sink-closure enumeration at the
// verification budget: every live call site of every declared sink must
// still resolve its payload input to a non-external origin. A live site
// receiving external input contradicts the falsifier outright;
// enumeration gaps or unresolvable inputs are insufficient scope, not
// contradictions. nv is mutated; "" means the closure confirms the
// FALSE candidate.
func (v Verifier) verifySinkClosure(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef, argIndex int) string {

	module := c.Vulnerability.Module
	if module == "" || len(subjects) == 0 {
		return "no module/subjects for sink closure"
	}
	cl, evs, err := v.Source.SinkClosure(ctx, claim.ConditionID, module, "", subjects, argIndex, verifyHops)
	if err != nil {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "sink-closure inventory failed: " + err.Error()
		return nv.Notes
	}
	for _, e := range evs {
		nv.EvidenceIDs = append(nv.EvidenceIDs, c.EvidenceGraph.AddEvidence(e))
	}
	c.EvidenceGraph.AddSinkClosure(cl)
	if !cl.Complete {
		var unsafe *domain.SinkSite
		var dead int
		for i := range cl.Sites {
			s := &cl.Sites[i]
			if !s.Live {
				dead++
				continue
			}
			if s.Origin == domain.OriginExternalUntrusted || s.Origin == domain.OriginExternalAuthenticated {
				unsafe = s
			}
		}
		if unsafe != nil {
			nv.Status = domain.NegativeContradicted
			nv.Notes = fmt.Sprintf("live sink site %s:%d (%s) receives %s input; FALSE contradicted",
				unsafe.File, unsafe.Line, unsafe.Sink, unsafe.Origin)
			return nv.Notes
		}
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = fmt.Sprintf("sink closure incomplete at verification depth: %d blocker(s), %d dead site(s) excluded",
			len(cl.Blockers), dead)
		return nv.Notes
	}
	return ""
}

// verifyIngress re-runs the dependency ingress-closure inventory at the
// deeper verification budget and re-checks what the evaluator's gate
// relied on: the inventory must still be complete, and every item must
// resolve to a safe origin. A clearly external item contradicts the
// falsifier; anything else that
// cannot be proven safe — unresolved origins, deployment-dependent
// sources, an incomplete closure — is insufficient scope, not a
// contradiction. nv is mutated; the return value is a short status note
// ("" when the closure confirms the FALSE candidate).
func (v Verifier) verifyIngress(ctx context.Context, c *domain.AnalysisCase,
	condID domain.ConditionID, nv *domain.NegativeVerification, subjects []domain.SymbolRef) string {

	module := c.Vulnerability.Module
	if module == "" || len(subjects) == 0 {
		return ""
	}
	closure, evs, err := v.Source.IngressInventory(ctx, module, subjects, verifyHops)
	if err != nil {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "ingress inventory failed: " + err.Error()
		return nv.Notes
	}
	for _, e := range evs {
		nv.EvidenceIDs = append(nv.EvidenceIDs, c.EvidenceGraph.AddEvidence(e))
	}
	closure.ConditionID = condID
	c.EvidenceGraph.AddIngressClosure(closure)
	if !closure.Complete {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = fmt.Sprintf("ingress closure incomplete at verification depth: %d blocker(s)",
			len(closure.Blockers))
		return nv.Notes
	}
	var unresolved int
	var external domain.IngressItem
	found := false
	for _, it := range closure.Items {
		switch it.Origin {
		case domain.OriginConstant, domain.OriginGenerated:
		case domain.OriginExternalUntrusted, domain.OriginExternalAuthenticated:
			external, found = it, true
		default:
			unresolved++
		}
	}
	if found {
		nv.Status = domain.NegativeContradicted
		nv.Notes = fmt.Sprintf("ingress item %s %s at %s:%d has origin %s and reaches %v; FALSE contradicted",
			external.Kind, external.Callee, external.File, external.Line, external.Origin, external.Reaches)
		return nv.Notes
	}
	if unresolved > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = fmt.Sprintf("ingress closure complete but %d of %d inventoried item(s) have unproven origin",
			unresolved, len(closure.Items))
		return nv.Notes
	}
	nv.EvidenceIDs = append(nv.EvidenceIDs, c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceDataFlow,
		Quality: domain.QualityDeterministic,
		Source:  "ingress-closure verification " + module,
		Tool:    "goanalysis.Index.IngressInventory",
		Content: fmt.Sprintf("complete=%v items=%d all-safe", closure.Complete, len(closure.Items)),
	}))
	return ""
}

func inputOriginVerification(origin domain.DataOrigin, falsifier string) domain.NegativeVerificationStatus {
	switch origin {
	case domain.OriginConfiguration:
		if falsifier == domain.FalsifierTrustedInfrastructure {
			return domain.NegativeVerified
		}
		return domain.NegativeContradicted
	case domain.OriginExternalUntrusted, domain.OriginExternalAuthenticated,
		domain.OriginDatabase, domain.OriginInternalService:
		return domain.NegativeContradicted
	case domain.OriginConstant, domain.OriginGenerated:
		return domain.NegativeVerified
	default:
		return domain.NegativeInsufficientScope
	}
}

// verifyGuardFalse verifies a VALIDATION FALSE ("every path to the sink is
// guarded"). The claim stands only when every traced sink site carries a
// Covers validation emitted by the bounded caller-guard climb — i.e. all
// expanded caller branches guard the argument. Missing sinks or partial
// coverage are INSUFFICIENT_SCOPE, not contradictions. extendNegativeScope
// still applies: a dynamic or build-gated call into the sink bypasses
// caller guards entirely.
func (v Verifier) verifyGuardFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification) domain.Claim {

	// (sink, arg) pairs recorded for this claim's condition — a guard on
	// arg0 must not certify arg1 of the same call.
	type sinkRef struct {
		site   domain.CallSite
		arg    int
		origin domain.DataOrigin
	}
	sinks := map[string]sinkRef{}
	for _, f := range c.EvidenceGraph.DataFlows {
		if claim.ConditionID != "" && f.ConditionID != claim.ConditionID {
			continue
		}
		if !knownInputOrigin(f.Origin) {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "unresolved argument origin cannot verify guard coverage"
			return setNeg(claim, nv)
		}
		key := fmt.Sprintf("%s:%d:%d", f.Sink.File, f.Sink.Line, f.Arg)
		sinks[key] = sinkRef{f.Sink, f.Arg, f.Origin}
	}
	if len(sinks) == 0 {
		// Older producers may record flows without a condition id.
		for _, f := range c.EvidenceGraph.DataFlows {
			if !knownInputOrigin(f.Origin) {
				nv.Status = domain.NegativeInsufficientScope
				nv.Notes = "unresolved argument origin cannot verify guard coverage"
				return setNeg(claim, nv)
			}
			key := fmt.Sprintf("%s:%d:%d", f.Sink.File, f.Sink.Line, f.Arg)
			sinks[key] = sinkRef{f.Sink, f.Arg, f.Origin}
		}
	}
	if len(sinks) == 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "no sink call sites recorded for the validation claim"
		return setNeg(claim, nv)
	}
	var uncovered []string
	var gated []string
	var conditional []string
	for key, s := range sinks {
		// A constant or generated argument is bounded by definition —
		// it needs no guard to certify it cannot violate the constraint.
		if s.origin == domain.OriginConstant || s.origin == domain.OriginGenerated {
			continue
		}
		guarded := false
		var condSites []domain.CallSite
		for _, val := range c.EvidenceGraph.Validations {
			// An Arg-scoped record constrains only that argument of the
			// sink call; Arg < 0 marks a record covering any position.
			if val.Arg >= 0 && s.arg >= 0 && val.Arg != s.arg {
				continue
			}
			if val.Covers != nil && val.Covers.File == s.site.File && val.Covers.Line == s.site.Line {
				guarded = true
				continue
			}
			// Only genuine guards can cover a sink — origin-assignment
			// records (Guard=false) just document where the value came
			// from. A guard nested in control flow is conditional: it
			// covers the sink only when the enclosing condition holds,
			// which is not something a FALSE claim may assume.
			if !val.Guard || val.File != s.site.File || val.Line <= 0 || val.Line >= s.site.Line {
				continue
			}
			if val.Conditional {
				condSites = append(condSites, val.CallSite)
				continue
			}
			guarded = true
		}
		if guarded {
			continue
		}
		// Conditional guards are the only records for this sink: check
		// whether the enclosing condition reads configuration — a knob the
		// analysis may not have resolved (spec §19 configuration
		// overrides). Downgrade either way, never silently accept.
		if len(condSites) > 0 {
			configHit := false
			if v.Source != nil {
				for _, gs := range condSites {
					if g, detail, err := v.Source.ConfigGated(ctx, gs); err == nil && g {
						configHit = true
						gated = append(gated, detail)
					}
				}
			}
			if !configHit {
				for _, gs := range condSites {
					conditional = append(conditional,
						fmt.Sprintf("%s:%d", gs.File, gs.Line))
				}
			}
			continue
		}
		uncovered = append(uncovered, key)
	}
	if len(gated) > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "covering guard(s) are conditional on configuration: " + strings.Join(gated, "; ")
		return setNeg(claim, nv)
	}
	if len(conditional) > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "guard(s) only hold under enclosing control-flow conditions: " +
			strings.Join(conditional, ", ")
		return setNeg(claim, nv)
	}
	if len(uncovered) > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = fmt.Sprintf("%d sink site(s) lack a covering guard: %s",
			len(uncovered), strings.Join(uncovered, ", "))
		return setNeg(claim, nv)
	}
	nv.Notes = fmt.Sprintf("all %d sink site(s) are covered by guards", len(sinks))
	return setNeg(claim, nv)
}

func knownInputOrigin(origin domain.DataOrigin) bool {
	return inputOriginVerification(origin, "") != domain.NegativeInsufficientScope
}

// hasExportedCoveredField reports whether any guard covering this claim's
// sinks protects an exported field — the only kind reflect.Value.Set can
// mutate. Unexported fields and claims with no field-backed guards return
// false: reflect cannot write locals or unexported fields, so there is
// nothing for a reflect_write marker to weaken.
func hasExportedCoveredField(c *domain.AnalysisCase, claim domain.Claim) bool {
	for _, val := range c.EvidenceGraph.Validations {
		if claim.ConditionID != "" &&
			!strings.Contains(val.Property, "cond="+string(claim.ConditionID)) {
			continue
		}
		name := ""
		firstField := func(rest string) string {
			if f := strings.Fields(rest); len(f) > 0 {
				return f[0]
			}
			return ""
		}
		if i := strings.Index(val.Property, "field-write "); i >= 0 {
			name = strings.TrimSuffix(firstField(val.Property[i+len("field-write "):]), ":")
		} else if i := strings.Index(val.Property, "write site of field "); i >= 0 {
			name = firstField(val.Property[i+len("write site of field "):])
		}
		if name == "" {
			continue
		}
		if name[0] >= 'A' && name[0] <= 'Z' {
			return true
		}
	}
	return false
}

func setNeg(cl domain.Claim, nv *domain.NegativeVerification) domain.Claim {
	cl.NegativeVerification = nv
	if nv.Status == domain.NegativeContradicted {
		cl.Result = domain.ClaimUnknown
		cl.Explanation += " | negative verification contradicted: " + nv.Notes
	}
	return cl
}

// symbolExported reports whether the subject name is an exported identifier
// (receiver-qualified subjects are split on the last dot).
func symbolExported(s domain.SymbolRef) bool {
	name := s.Symbol
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return name != "" && name[0] >= 'A' && name[0] <= 'Z'
}

// symbolIsMethod reports whether the subject name represents a method on a type
// (receiver-qualified, e.g. "Type.Method" or "(*Type).Method") rather than a
// package-level standalone function.
func symbolIsMethod(s domain.SymbolRef) bool {
	return strings.Contains(s.Symbol, ".")
}

// unreferenceable returns the subjects product code cannot legally name:
// anything inside an `internal` package tree (unimportable outside the
// module subtree) or whose identifier — or qualifying receiver type — is
// unexported. For such subjects a "zero product references" observation is
// vacuous, so reference-counting falsifiers must not rely on them.
func unreferenceable(subjects []domain.SymbolRef) []string {
	var out []string
	for _, s := range subjects {
		if !productReferenceable(s) {
			out = append(out, s.Package+"."+s.Symbol)
		}
	}
	return out
}

func productReferenceable(s domain.SymbolRef) bool {
	for _, seg := range strings.Split(s.Package, "/") {
		if seg == "internal" {
			return false
		}
	}
	for _, seg := range strings.Split(s.Symbol, ".") {
		seg = strings.TrimLeft(seg, "(*")
		seg = strings.TrimRight(seg, ")")
		if seg == "" || seg[0] < 'A' || seg[0] > 'Z' {
			return false
		}
	}
	return true
}

// linknameNames reports whether a go:linkname pragma targets the subject.
func linknameNames(detail string, s domain.SymbolRef) bool {
	return strings.Contains(detail, s.Symbol)
}

// verifySnapshotFalse accepts FALSE claims that are decided by snapshot
// facts (platform, runtime toolchain) rather than code-scope searches:
// there is no call-site scope to widen, so the negative is VERIFIED when
// the evaluator produced a mismatch explanation.
func verifySnapshotFalse(claim domain.Claim, nv *domain.NegativeVerification) domain.Claim {
	if claim.Explanation == "" {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "FALSE without a recorded snapshot-fact mismatch"
		return setNeg(claim, nv)
	}
	nv.Notes = "FALSE is decided by product snapshot facts, not call-site scope"
	return setNeg(claim, nv)
}
