package evaluator

import (
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// ConditionEvaluator assigns a TRUE/FALSE/UNKNOWN claim to a condition using
// only deterministic evidence already present in the graph.
type ConditionEvaluator interface {
	CanEvaluate(cond domain.Condition) bool
	Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim
}

// SymbolReachable evaluates SYMBOL_REACHABLE conditions from govulncheck
// call paths stored in the EvidenceGraph.
//
// Semantics per spec: a found call path to the root-cause symbol is a TRUE.
// A completed govulncheck run without such a path yields a FALSE *candidate*
// that still requires negative verification. A failed/absent run yields
// UNKNOWN — tool failure is never negative evidence.
type SymbolReachable struct{}

func (SymbolReachable) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionSymbolReachable
}

func (SymbolReachable) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
	}
	symbols := reachabilitySubjects(cond, c)
	if len(symbols) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no subject symbol: set condition.subject or resolve root cause first")
		return claim
	}

	if !govulncheckRan(c) {
		claim.Limitations = append(claim.Limitations, "govulncheck did not run or failed")
		return claim
	}

	matched := map[string]bool{}
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			for _, sym := range symbols {
				if frameMatches(fr, sym) {
					matched[sym.Package+"."+sym.Symbol] = true
					if cp.EvidenceID != "" {
						claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, cp.EvidenceID)
					}
				}
			}
		}
	}
	if len(matched) > 0 {
		claim.Result = domain.ClaimTrue
		claim.Explanation = "govulncheck produced call path(s) to the affected symbol(s)"
		return claim
	}
	claim.EvidenceIDs = nil
	claim.Result = domain.ClaimFalse
	claim.Explanation = fmt.Sprintf("govulncheck found no call path to any of %d affected symbol(s)", len(symbols))
	claim.Limitations = append(claim.Limitations,
		"FALSE is a candidate: interfaces/reflection/plugins may bypass static reachability")
	return claim
}

func reachabilitySubjects(cond domain.Condition, c *domain.AnalysisCase) []domain.SymbolRef {
	if cond.Subject != nil {
		return []domain.SymbolRef{*cond.Subject}
	}
	var out []domain.SymbolRef
	if c.Exploit != nil {
		out = append(out, c.Exploit.RootCauses...)
	}
	if len(out) == 0 && c.RootCause != nil {
		for _, rc := range c.RootCause.RootCauses {
			out = append(out, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
		}
	}
	return out
}

func govulncheckRan(c *domain.AnalysisCase) bool {
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Kind == domain.EvidenceGovulncheck {
			return true
		}
	}
	return false
}

func appendUniqueID(ids []domain.EvidenceID, id domain.EvidenceID) []domain.EvidenceID {
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}

func frameMatches(cs domain.CallSite, sym domain.SymbolRef) bool {
	if cs.Package != sym.Package {
		return false
	}
	return cs.Function == sym.Symbol
}
