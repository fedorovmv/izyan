package evaluator

import (
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

type VerdictEvaluator struct{}

// Evaluate is a pure function: no LLM, FS, DB or network. NOT_AFFECTED is
// produced only by a deterministic FALSE in the affected-resolution chain;
// FALSE exploit conditions require a VERIFIED negative check; anything else
// is INCONCLUSIVE.
func (VerdictEvaluator) Evaluate(affected domain.AffectedResult, model domain.ExploitModel, claims []domain.Claim) domain.VerdictResult {
	switch {
	case affected.ModulePresent == domain.ClaimFalse:
		reason := "vulnerable module is not part of the product dependency graph"
		if len(affected.CheckedModules) > 0 {
			reason = fmt.Sprintf("none of the affected module(s) %s resolve to a product dependency (go list -m all)",
				joinPaths(affected.CheckedModules))
		}
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      reason,
			EvidenceIDs: affected.EvidenceIDs,
		}
	case affected.VersionAffected == domain.ClaimFalse:
		reason := "resolved dependency version is outside affected range"
		if affected.ResolvedVersion != "" {
			reason = fmt.Sprintf("resolved version %s is outside the affected range", affected.ResolvedVersion)
		}
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      reason,
			EvidenceIDs: affected.EvidenceIDs,
		}
	case affected.PackagePresent == domain.ClaimFalse:
		reason := "affected package is not imported by the product build"
		if len(affected.CheckedPackages) > 0 {
			reason = fmt.Sprintf("affected package(s) %s are absent from the product's transitive import closure (go list -deps -test ./...) — the code is not linked into the product",
				joinPaths(affected.CheckedPackages))
		}
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      reason,
			EvidenceIDs: affected.EvidenceIDs,
			Limitations: affected.Limitations,
		}
	case affected.BuildRelevant == domain.ClaimFalse:
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      "affected packages are constrained to other platforms/build configurations",
			EvidenceIDs: affected.EvidenceIDs,
		}
	}

	byCondition := make(map[domain.ConditionID]domain.Claim, len(claims))
	for _, c := range claims {
		byCondition[c.ConditionID] = c
	}

	allTrue := len(model.MandatoryConditions) > 0
	for _, condition := range model.MandatoryConditions {
		claim, ok := byCondition[condition.ID]
		if !ok || claim.Result == domain.ClaimUnknown {
			allTrue = false
			continue
		}
		if claim.Result == domain.ClaimFalse {
			allTrue = false
			if claim.Falsifier != "" && claim.NegativeVerification != nil && claim.NegativeVerification.Status == domain.NegativeVerified {
				return domain.VerdictResult{
					Verdict:      domain.VerdictNoExploitPathFound,
					Reason:       "mandatory exploit condition is proven false",
					ConditionIDs: []domain.ConditionID{condition.ID},
					EvidenceIDs:  claim.EvidenceIDs,
				}
			}
		}
	}

	if allTrue {
		return domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
			Reason:  "all mandatory exploit conditions are satisfied",
		}
	}

	var unresolved []string
	for _, condition := range model.MandatoryConditions {
		claim, ok := byCondition[condition.ID]
		if !ok || claim.Result != domain.ClaimTrue {
			unresolved = append(unresolved, string(condition.ID))
		}
	}
	reason := "one or more mandatory exploit conditions remain unresolved"
	if len(unresolved) > 0 {
		reason += ": " + strings.Join(unresolved, ", ")
	}
	return domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  reason,
	}
}

func joinPaths(paths []string) string {
	q := make([]string, len(paths))
	for i, p := range paths {
		q[i] = `"` + p + `"`
	}
	return strings.Join(q, ", ")
}
