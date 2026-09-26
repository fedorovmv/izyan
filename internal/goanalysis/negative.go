package goanalysis

import (
	"context"
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Verifier performs a bounded negative verification pass on FALSE claims.
// It searches for alternate references, dynamic escapes and provenance
// bypasses that static analysis may have missed. A FALSE claim only survives
// when the falsification pass finds no counterexample within the searchable
// scope; contradictions demote it back to UNKNOWN.
type Verifier struct {
	Source *Index
}

// VerifyFalse attempts to falsify a FALSE claim for cond across all of its
// subjects and returns the updated claim with its NegativeVerification.
func (v Verifier) VerifyFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition) domain.Claim {

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
			case "reflect", "unsafe", "plugin":
				// reflect/plugin can only look up *exported* identifiers; an
				// unexported sink is unreachable to them. unsafe alone calls
				// nothing — it matters through linkname/func_value, which are
				// checked per-symbol above.
				if anyExported && !dynSeen[m.Kind] {
					dynSeen[m.Kind] = true
					nv.Limitations = append(nv.Limitations,
						m.Kind+" usage in product widens the call graph; static negative verification is weaker")
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
			out = v.verifyReachableFalse(claim, nv, subjects, allSites)
		case domain.ConditionAttackerControl, domain.ConditionInputConstraint:
			out = v.verifyInputFalse(ctx, c, claim, nv, subjects, cond.ArgIndex)
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
	for _, m := range missing {
		refs += len(allSites[m])
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
func (v Verifier) verifyReachableFalse(claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef,
	allSites map[string][]domain.CallSite) domain.Claim {

	total := 0
	for _, s := range subjects {
		total += len(allSites[s.Package+"."+s.Symbol])
	}
	if total == 0 {
		nv.Notes = fmt.Sprintf("none of %d affected symbol(s) is referenced in product code",
			len(subjects))
		return setNeg(claim, nv)
	}
	nv.Status = domain.NegativeInsufficientScope
	nv.Notes = fmt.Sprintf("%d static reference(s) across %d subject(s) exist without a govulncheck path; "+
		"cannot exclude dynamic dispatch or un-modeled entrypoints", total, len(subjects))
	return setNeg(claim, nv)
}

// verifyInputFalse verifies the FALSE candidate for ATTACKER_CONTROL /
// INPUT_CONSTRAINT: every call site of every subject must pass arguments
// whose provenance resolves to a non-external origin (argIndex < 0 covers
// all arguments).
func (v Verifier) verifyInputFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef, argIndex int) domain.Claim {

	totalCallers := 0
	for _, subj := range subjects {
		callers, err := v.Source.FindCallers(ctx, subj)
		if err != nil {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "caller search failed: " + err.Error()
			return setNeg(claim, nv)
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
				flows, evs, err = v.Source.TraceAllArguments(ctx, site)
			} else {
				var f domain.DataFlow
				f, evs, err = v.Source.TraceArgument(ctx, site, argIndex)
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
				if flow.Origin == domain.OriginUnknown ||
					flow.Origin == domain.OriginExternalUntrusted ||
					flow.Origin == domain.OriginExternalAuthenticated ||
					flow.Origin == domain.OriginConfiguration ||
					flow.Origin == domain.OriginDatabase ||
					flow.Origin == domain.OriginInternalService {
					nv.Status = domain.NegativeContradicted
					nv.Notes = fmt.Sprintf("call site %s passes %s input (%s); FALSE contradicted",
						site.Function, flow.Origin, flow.Summary)
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
	nv.Notes = fmt.Sprintf("all %d call site(s) across %d subject(s) pass non-external input",
		totalCallers, len(subjects))
	return setNeg(claim, nv)
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

// linknameNames reports whether a go:linkname pragma targets the subject.
func linknameNames(detail string, s domain.SymbolRef) bool {
	return strings.Contains(detail, s.Symbol)
}
