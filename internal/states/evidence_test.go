package states

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

func TestActCollectEvidence_MissingCallOmitted(t *testing.T) {
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "missingcall"))
	if err != nil {
		t.Fatal(err)
	}

	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-REACH",
					Kind:      domain.ConditionSymbolReachable,
					Mandatory: true,
					Subjects: []domain.SymbolRef{
						{Package: "example.com/dep/vuln", Symbol: "MapClaims.Valid"},
					},
					Params: map[string]string{"pipeline": "MapClaims.Valid"},
				},
				{
					ID:        "C-OMISSION",
					Kind:      domain.ConditionMissingCall,
					Mandatory: true,
					Subjects: []domain.SymbolRef{
						{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"},
					},
					Params: map[string]string{
						"pipeline":        "MapClaims.Valid",
						domain.ParamCheck: domain.CheckMissingCall,
					},
				},
			},
		},
	}

	h := CollectEvidence{Source: &goanalysis.Index{Dir: product}}
	h.actCollectEvidence(context.Background(), c)

	ev := c.EvidenceGraph.EvidenceByID("EV-MISSING-CALL")
	if ev == nil {
		t.Fatal("expected EV-MISSING-CALL in evidence graph, found nil")
	}
	if ev.Kind != domain.EvidenceValidation {
		t.Errorf("ev.Kind = %v, want %v", ev.Kind, domain.EvidenceValidation)
	}
	if ev.Quality != domain.QualityDeterministic {
		t.Errorf("ev.Quality = %v, want %v", ev.Quality, domain.QualityDeterministic)
	}
	if !strings.Contains(ev.Content, "MapClaims.VerifyAudience") || !strings.Contains(ev.Content, "MapClaims.Valid") {
		t.Errorf("ev.Content missing symbols: %s", ev.Content)
	}
}

func TestActCollectEvidence_MissingCallInvoked(t *testing.T) {
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "missingcallinvoked"))
	if err != nil {
		t.Fatal(err)
	}

	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{
				{
					ID:        "C-REACH",
					Kind:      domain.ConditionSymbolReachable,
					Mandatory: true,
					Subjects: []domain.SymbolRef{
						{Package: "example.com/dep/vuln", Symbol: "MapClaims.Valid"},
					},
					Params: map[string]string{"pipeline": "MapClaims.Valid"},
				},
				{
					ID:        "C-OMISSION",
					Kind:      domain.ConditionMissingCall,
					Mandatory: true,
					Subjects: []domain.SymbolRef{
						{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"},
					},
					Params: map[string]string{
						"pipeline":        "MapClaims.Valid",
						domain.ParamCheck: domain.CheckMissingCall,
					},
				},
			},
		},
	}

	h := CollectEvidence{Source: &goanalysis.Index{Dir: product}}
	h.actCollectEvidence(context.Background(), c)

	if ev := c.EvidenceGraph.EvidenceByID("EV-MISSING-CALL"); ev != nil {
		t.Fatalf("expected no EV-MISSING-CALL when check is invoked, got: %+v", ev)
	}
	ev := c.EvidenceGraph.EvidenceByID("EV-CHECK-PRESENT")
	if ev == nil {
		t.Fatal("expected EV-CHECK-PRESENT when check is invoked, got nil")
	}
	if !strings.Contains(ev.Content, "invoked in product code") {
		t.Errorf("ev.Content unexpected: %s", ev.Content)
	}
}
