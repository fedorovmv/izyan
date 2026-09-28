package evaluator

import (
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Authentication evaluates AUTHENTICATION_CONDITION conditions — whether
// the inbound surface feeding the vulnerable path is wired behind an
// authentication/authorization check.
//
//	TRUE — auth-middleware facts were observed next to an inbound
//	  listener (Use/With middleware, grpc interceptors, wrapped
//	  handlers): requests reaching the product plausibly pass an auth
//	  check, satisfying a "requires authentication" condition.
//	UNKNOWN — no auth wiring observed, or no inbound listener resolved.
//
// The evaluator never returns FALSE. Absence of middleware wiring is
// not proof the surface is unauthenticated — per-handler checks,
// gateway auth and deployment-level filters are outside this scan — and
// a FALSE here feeds the dangerous direction: an auth-required
// vulnerability declared unsatisfiable on an unverified negative.
type Authentication struct{}

func (Authentication) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionAuthn
}

func (Authentication) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.Authentication",
	}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if strings.Contains(e.Source, "InboundAuthFacts") {
			claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, e.ID)
		}
	}
	var authFacts []string
	listeners := 0
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if f.Direction != "inbound" {
			continue
		}
		switch f.Kind {
		case "auth-middleware":
			authFacts = append(authFacts,
				fmt.Sprintf("%s at %s:%d", f.Target, f.File, f.Line))
		case "listener":
			listeners++
		}
	}
	if len(authFacts) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no auth-middleware wiring observed near listeners; per-handler, gateway or deployment auth is outside this scan — absence is not proof")
		return claim
	}
	if listeners == 0 {
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("auth-middleware wiring observed (%s) but no inbound listener resolved — the wired surface may be dead code", strings.Join(authFacts, "; ")))
		return claim
	}
	claim.Result = domain.ClaimTrue
	claim.Explanation = fmt.Sprintf("inbound surface wired behind auth check(s): %s",
		strings.Join(authFacts, "; "))
	claim.Limitations = append(claim.Limitations,
		"middleware matched by name and position; per-route coverage is not proven — some paths may bypass the check")
	return claim
}
