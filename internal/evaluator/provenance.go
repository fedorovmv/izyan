package evaluator

import (
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// ArgumentOrigin evaluates ATTACKER_CONTROL and INPUT_CONSTRAINT conditions
// from DataFlow entries recorded by the argument-provenance collector.
//
// TRUE  — at least one trace proves EXTERNAL_UNTRUSTED/AUTHENTICATED origin.
// FALSE (candidate) — every traced call site has a non-external origin
// (CONSTANT/GENERATED/CONFIGURATION); requires negative verification.
// UNKNOWN — missing traces or unresolvable origins.
type ArgumentOrigin struct{}

func (ArgumentOrigin) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionAttackerControl || cond.Kind == domain.ConditionInputConstraint
}

func (ArgumentOrigin) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer:    "evaluator.ArgumentOrigin",
	}
	flows := flowsFor(c, cond.ID)
	if len(flows) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no argument-provenance data flows recorded for this condition")
		return claim
	}
	var safe, external, unknown, deployDependent int
	for _, f := range flows {
		switch f.Origin {
		case domain.OriginExternalUntrusted, domain.OriginExternalAuthenticated:
			external++
		case domain.OriginConfiguration, domain.OriginDatabase, domain.OriginInternalService:
			// Deployment-controlled sources: trust boundary is a deployment
			// property — we cannot prove the value is not attacker-influenced.
			deployDependent++
		case domain.OriginUnknown:
			unknown++
		default:
			safe++
		}
	}
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Kind == domain.EvidenceSourceSnippet || e.Kind == domain.EvidenceDataFlow {
			claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
		}
	}
	switch {
	case external > 0:
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf("%d call site(s) receive externally controlled input", external)
	case unknown > 0:
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("%d call site(s) have unresolvable argument origin", unknown))
	case deployDependent > 0:
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("%d call site(s) receive config/service-provided input; attacker control depends on deployment trust boundary — cannot prove non-external", deployDependent))
	default:
		claim.Result = domain.ClaimFalse
		claim.Explanation = fmt.Sprintf("all %d traced call site(s) receive non-external input", safe)
		claim.Limitations = append(claim.Limitations,
			"FALSE is a candidate: provenance coverage is limited to direct call sites")
	}
	return claim
}

func flowsFor(c *domain.AnalysisCase, id domain.ConditionID) []domain.DataFlow {
	var out []domain.DataFlow
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID == id {
			out = append(out, f)
		}
	}
	return out
}
