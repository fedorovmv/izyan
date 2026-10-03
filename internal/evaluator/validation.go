package evaluator

import (
	"fmt"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Validation evaluates VALIDATION conditions. In exploit-model semantics a
// VALIDATION condition asserts "the attacker-controlled input reaches the
// sink without effective validation". Deterministic rule:
//
//	FALSE candidate — every traced sink call site is preceded by a guard
//	  (validation) on the same file path → mitigated on all observed paths;
//	  still requires negative verification.
//	UNKNOWN — no flows, partial guard coverage, or no guards anywhere
//	  (absence of guards is not proof of absence).
type Validation struct{}

func (Validation) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionValidation
}

func (Validation) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.Validation",
	}
	flows := flowsFor(c, cond.ID)
	if len(flows) == 0 {
		flows = c.EvidenceGraph.DataFlows
	}
	if len(flows) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no data flows recorded; cannot locate sink call sites")
		return claim
	}
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Kind == domain.EvidenceValidation || e.Kind == domain.EvidenceSourceSnippet {
			claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
		}
	}
	guarded, total := 0, len(flows)
	for _, f := range flows {
		if hasGuardBefore(c.EvidenceGraph.Validations, f.Sink) {
			guarded++
		}
	}
	switch {
	case guarded == total:
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierGuards
		claim.Explanation = fmt.Sprintf("all %d traced sink call site(s) are preceded by validation guards", total)
		claim.Limitations = append(claim.Limitations,
			"FALSE is a candidate: guard effectiveness is not proven by presence alone")
	case guarded > 0:
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("validation guards on %d of %d call sites; partial coverage", guarded, total))
	default:
		claim.Limitations = append(claim.Limitations,
			"no validation guards found before sink call sites; coverage may be incomplete")
	}
	return claim
}

// hasGuardBefore reports whether a validation in the same file precedes the
// sink call site, or a caller-frame guard was recorded as covering it.
func hasGuardBefore(vals []domain.Validation, sink domain.CallSite) bool {
	for _, v := range vals {
		if v.Covers != nil && v.Covers.File == sink.File && v.Covers.Line == sink.Line {
			return true
		}
		if v.File == sink.File && v.Line > 0 && sink.Line > 0 && v.Line < sink.Line {
			return true
		}
	}
	return false
}
