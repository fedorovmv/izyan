package evaluator

import "example.com/vuln-analyzer/internal/domain"

type VerdictEvaluator struct{}

// Evaluate is a pure function: no LLM, FS, DB or network. NOT_AFFECTED is
// produced only by a deterministic FALSE in the affected-resolution chain;
// FALSE exploit conditions require a VERIFIED negative check; anything else
// is INCONCLUSIVE.
func (VerdictEvaluator) Evaluate(affected domain.AffectedResult, model domain.ExploitModel, claims []domain.Claim) domain.VerdictResult {
	switch {
	case affected.ModulePresent == domain.ClaimFalse:
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      "vulnerable module is not part of the product dependency graph",
			EvidenceIDs: affected.EvidenceIDs,
		}
	case affected.VersionAffected == domain.ClaimFalse:
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      "resolved dependency version is outside affected range",
			EvidenceIDs: affected.EvidenceIDs,
		}
	case affected.PackagePresent == domain.ClaimFalse:
		return domain.VerdictResult{
			Verdict:     domain.VerdictNotAffected,
			Reason:      "affected package is not imported by the product build",
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
			if claim.NegativeVerification != nil && claim.NegativeVerification.Status == domain.NegativeVerified {
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

	return domain.VerdictResult{
		Verdict: domain.VerdictInconclusive,
		Reason:  "one or more mandatory exploit conditions remain unresolved",
	}
}
