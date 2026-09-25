package evaluator

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func affectedAllTrue() domain.AffectedResult {
	return domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
	}
}

func TestVerdictNotAffected(t *testing.T) {
	e := VerdictEvaluator{}
	for field, res := range map[string]domain.AffectedResult{
		"module":  {ModulePresent: domain.ClaimFalse},
		"version": {ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse},
		"package": {ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimFalse},
		"build":   {ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimFalse},
	} {
		got := e.Evaluate(res, domain.ExploitModel{}, nil)
		if got.Verdict != domain.VerdictNotAffected {
			t.Errorf("%s FALSE: got %s, want NOT_AFFECTED", field, got.Verdict)
		}
	}
}

func TestVerdictExploitable(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}, {ID: "C2"}},
	}
	claims := []domain.Claim{
		{ConditionID: "C1", Result: domain.ClaimTrue},
		{ConditionID: "C2", Result: domain.ClaimTrue},
	}
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictExploitable {
		t.Fatalf("got %s, want EXPLOITABLE", got.Verdict)
	}
}

func TestVerdictNoExploitPathFoundRequiresVerification(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}},
	}
	unverified := []domain.Claim{{ConditionID: "C1", Result: domain.ClaimFalse}}
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, unverified)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("unverified FALSE: got %s, want INCONCLUSIVE", got.Verdict)
	}

	verified := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	got = VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, verified)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verified FALSE: got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

func TestVerdictInconclusiveOnUnknown(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}},
	}
	claims := []domain.Claim{{ConditionID: "C1", Result: domain.ClaimUnknown}}
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
	}
}

// An empty exploit model must never produce EXPLOITABLE.
func TestVerdictNoModelNotExploitable(t *testing.T) {
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), domain.ExploitModel{}, nil)
	if got.Verdict == domain.VerdictExploitable {
		t.Fatal("empty exploit model produced EXPLOITABLE")
	}
}
