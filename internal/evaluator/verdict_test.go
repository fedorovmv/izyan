package evaluator

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
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
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verified FALSE without falsifier: got %s, want INCONCLUSIVE", got.Verdict)
	}
	verified[0].Falsifier = domain.FalsifierConstantOrGeneratedInput
	got = VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, verified)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verified FALSE: got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// An advisory-declared sink that failed source resolution narrows the
// modeled mandatory set — EXPLOITABLE on a partial model would claim
// completeness the pipeline did not prove.
func TestVerdictExploitableBlockedByUnresolvedSubjects(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1"}},
		UnresolvedSubjects: []domain.SymbolRef{
			{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"},
		},
	}
	claims := []domain.Claim{{ConditionID: "C1", Result: domain.ClaimTrue}}
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
	}
	if !strings.Contains(got.Reason, "RouteAndProcess") {
		t.Fatalf("reason must name the unresolved sink: %q", got.Reason)
	}
}

// A verified FALSE on the grouped reachability falsifier covers every
// advisory-declared symbol — including the unresolved one — so NEPF stays
// sound on an incomplete model.
func TestVerdictNepfAllowedForCoveringFalsifier(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1", Kind: domain.ConditionSymbolReachable}},
		UnresolvedSubjects:  []domain.SymbolRef{{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}},
	}
	claims := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// A verified FALSE bound to the resolved sinks' arguments leaves the
// unresolved sink's exploit shape unconstrained — no NEPF.
func TestVerdictNepfBlockedForNarrowFalsifier(t *testing.T) {
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C1", Kind: domain.ConditionInputConstraint}},
		UnresolvedSubjects:  []domain.SymbolRef{{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}},
	}
	claims := []domain.Claim{{
		ConditionID: "C1",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierConstantOrGeneratedInput,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
	}
}

// A verified locus-package-absent falsifier discharges unresolved subjects
// that are themselves locus members — the same build-graph absence covers
// them.
func TestVerdictNepfAllowedForLocusCoveringUnresolved(t *testing.T) {
	locus := domain.SymbolRef{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable,
			Params:   map[string]string{domain.ParamCheck: domain.CheckLocus},
			Subjects: []domain.SymbolRef{locus},
		}},
		UnresolvedSubjects: []domain.SymbolRef{locus},
	}
	claims := []domain.Claim{{
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusPackageAbsent,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("got %s, want NO_EXPLOIT_PATH_FOUND", got.Verdict)
	}
}

// An unresolved subject outside the locus set is not covered by the locus
// falsifier — the package absence it verified says nothing about that
// symbol's exploit shape.
func TestVerdictNepfBlockedForLocusOutsideUnresolved(t *testing.T) {
	locus := domain.SymbolRef{Package: "example.com/dep/internal/mode", Symbol: "RouteAndProcess"}
	other := domain.SymbolRef{Package: "example.com/dep/internal/transport", Symbol: "HandleStreams"}
	model := domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{
			ID: "C-LOCUS", Kind: domain.ConditionSymbolReachable,
			Params:   map[string]string{domain.ParamCheck: domain.CheckLocus},
			Subjects: []domain.SymbolRef{locus},
		}},
		UnresolvedSubjects: []domain.SymbolRef{locus, other},
	}
	claims := []domain.Claim{{
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusPackageAbsent,
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified,
		},
	}}
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), model, claims)
	if got.Verdict != domain.VerdictInconclusive {
		t.Fatalf("got %s, want INCONCLUSIVE", got.Verdict)
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
	if !strings.Contains(got.Reason, "C1") {
		t.Fatalf("inconclusive reason must name unresolved conditions: %q", got.Reason)
	}
}

// NOT_AFFECTED reasons name the checked subject — a bare code is not a
// justification a reader can audit.
func TestNotAffectedReasonNamesProbedSubjects(t *testing.T) {
	res := domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimFalse,
		CheckedPackages: []string{"example.com/dep/vuln"},
	}
	got := VerdictEvaluator{}.Evaluate(res, domain.ExploitModel{}, nil)
	if !strings.Contains(got.Reason, "example.com/dep/vuln") {
		t.Fatalf("reason must name probed packages: %q", got.Reason)
	}
}

// An empty exploit model must never produce EXPLOITABLE.
func TestVerdictNoModelNotExploitable(t *testing.T) {
	got := VerdictEvaluator{}.Evaluate(affectedAllTrue(), domain.ExploitModel{}, nil)
	if got.Verdict == domain.VerdictExploitable {
		t.Fatal("empty exploit model produced EXPLOITABLE")
	}
}
