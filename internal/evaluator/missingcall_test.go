package evaluator

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestMissingCallEvaluator_TrueWhenOmitted(t *testing.T) {
	eval := MissingCall{}
	cond := domain.Condition{
		ID:   "C-OMISSION",
		Kind: domain.ConditionMissingCall,
		Subjects: []domain.SymbolRef{
			{Package: "github.com/golang-jwt/jwt", Symbol: "MapClaims.VerifyAudience"},
		},
		Params: map[string]string{
			"pipeline": "MapClaims.Valid",
		},
	}
	if !eval.CanEvaluate(cond) {
		t.Fatal("MissingCall must claim ConditionMissingCall")
	}

	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				{
					ID:      "EV-MISSING-CALL",
					Kind:    domain.EvidenceValidation,
					Quality: domain.QualityDeterministic,
					Source:  "source index: missing-call verification",
					Tool:    "goanalysis.Index.CheckMissingCall",
					Content: "security check MapClaims.VerifyAudience is omitted on active pipeline MapClaims.Valid; path: main -> Valid; check invocations on path: 0",
				},
			},
		},
	}

	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("expected ClaimTrue, got %s (explanation: %s)", claim.Result, claim.Explanation)
	}
	if len(claim.EvidenceIDs) == 0 || claim.EvidenceIDs[0] != "EV-MISSING-CALL" {
		t.Fatalf("expected evidence ID EV-MISSING-CALL, got %v", claim.EvidenceIDs)
	}
}

func TestMissingCallEvaluator_FalseWhenCheckInvoked(t *testing.T) {
	eval := MissingCall{}
	cond := domain.Condition{
		ID:   "C-OMISSION",
		Kind: domain.ConditionMissingCall,
		Subjects: []domain.SymbolRef{
			{Package: "github.com/golang-jwt/jwt", Symbol: "MapClaims.VerifyAudience"},
		},
		Params: map[string]string{
			"pipeline": "MapClaims.Valid",
		},
	}

	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				{
					ID:      "EV-CHECK-PRESENT",
					Kind:    domain.EvidenceValidation,
					Quality: domain.QualityDeterministic,
					Source:  "source index: check-call verification",
					Tool:    "goanalysis.Index.CheckMissingCall",
					Content: "security check MapClaims.VerifyAudience is invoked in product code at main.go:20",
				},
			},
		},
	}

	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("expected ClaimFalse, got %s (explanation: %s)", claim.Result, claim.Explanation)
	}
	if claim.Falsifier != domain.FalsifierGuards {
		t.Fatalf("expected FalsifierGuards, got %s", claim.Falsifier)
	}
	if len(claim.EvidenceIDs) == 0 || claim.EvidenceIDs[0] != "EV-CHECK-PRESENT" {
		t.Fatalf("expected evidence ID EV-CHECK-PRESENT, got %v", claim.EvidenceIDs)
	}
}

func TestMissingCallEvaluator_UnknownWhenNoEvidence(t *testing.T) {
	eval := MissingCall{}
	cond := domain.Condition{
		ID:   "C-OMISSION",
		Kind: domain.ConditionMissingCall,
		Subjects: []domain.SymbolRef{
			{Package: "github.com/golang-jwt/jwt", Symbol: "MapClaims.VerifyAudience"},
		},
		Params: map[string]string{
			"pipeline": "MapClaims.Valid",
		},
	}

	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{},
	}

	claim := eval.Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("expected ClaimUnknown, got %s", claim.Result)
	}
}
