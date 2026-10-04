package evaluator

import (
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// MissingCall evaluates MISSING_CALL conditions.
// In exploit-model semantics, a MISSING_CALL condition asserts that a security
// check method (e.g. MapClaims.VerifyAudience) is omitted across the active execution
// path of a reached validation pipeline (e.g. MapClaims.Valid).
//
// Deterministic rules:
//   - TRUE: EV-MISSING-CALL evidence is present in the evidence graph, proving
//     the pipeline is reached from product code and the check has 0 invocations.
//   - FALSE candidate: EV-CHECK-PRESENT evidence is present, proving the check
//     is explicitly invoked. Uses FalsifierGuards.
//   - UNKNOWN: neither evidence is present, or check failed.
type MissingCall struct{}

func (MissingCall) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionMissingCall || cond.Params[domain.ParamCheck] == domain.CheckMissingCall
}

func (MissingCall) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.MissingCall",
	}
	if c == nil {
		return claim
	}

	for _, e := range c.EvidenceGraph.Evidence {
		if e.ID == "EV-MISSING-CALL" || strings.HasPrefix(string(e.ID), "EV-MISSING-CALL") {
			if len(cond.Subjects) == 0 || strings.Contains(e.Content, cond.Subjects[0].Symbol) {
				claim.Result = domain.ClaimTrue
				claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
				claim.Explanation = e.Content
				return claim
			}
		}
		if e.ID == "EV-CHECK-PRESENT" || strings.HasPrefix(string(e.ID), "EV-CHECK-PRESENT") {
			if len(cond.Subjects) == 0 || strings.Contains(e.Content, cond.Subjects[0].Symbol) {
				claim.Result = domain.ClaimFalse
				claim.Falsifier = domain.FalsifierGuards
				claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
				claim.Explanation = e.Content
				claim.Limitations = append(claim.Limitations, "FALSE is a candidate: check invocation presence does not guarantee path-specific effectiveness")
				return claim
			}
		}
	}

	claim.Limitations = append(claim.Limitations, "no deterministic missing-call evidence collected for condition")
	return claim
}
