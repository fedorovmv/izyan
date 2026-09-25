package goanalysis

import (
	"context"
	"fmt"

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
			case "func_value", "linkname":
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("symbol %s escapes static call graph via %s at %s:%d",
					subj.Package+"."+subj.Symbol, m.Kind, m.File, m.Line)
				return setNeg(claim, nv)
			case "reflect", "unsafe", "plugin":
				nv.Limitations = append(nv.Limitations,
					m.Kind+" usage in product widens the call graph; static negative verification is weaker")
			}
		}
	}

	switch cond.Kind {
	case domain.ConditionSymbolReachable:
		return v.verifyReachableFalse(claim, nv, subjects, allSites)
	case domain.ConditionAttackerControl, domain.ConditionInputConstraint:
		return v.verifyInputFalse(ctx, c, claim, nv, subjects, cond.ArgIndex)
	default:
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "no falsification strategy for condition kind " + string(cond.Kind)
		return setNeg(claim, nv)
	}
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
					flow.Origin == domain.OriginExternalAuthenticated {
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
