package states

import (
	"context"
	"path/filepath"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/goanalysis"
)

func TestCollectSinkClosureKeepsAdvisorySymbolsKnownOnly(t *testing.T) {
	repo, err := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	if err != nil {
		t.Fatal(err)
	}
	subject := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:              "GO-TEST-1",
			Module:          "example.com/dep",
			AffectedSymbols: []domain.SymbolRef{subject},
		},
	}
	CollectEvidence{Source: &goanalysis.Index{Dir: repo}}.collectSinkClosure(
		context.Background(), c,
		domain.Condition{ID: "C-INPUT", Kind: domain.ConditionAttackerControl},
		[]domain.SymbolRef{subject},
	)
	cl := c.EvidenceGraph.SinkClosureFor("C-INPUT")
	if cl == nil {
		t.Fatal("sink closure was not persisted")
	}
	if cl.Basis != "" || cl.Complete {
		t.Fatalf("advisory affected-symbol membership created complete sink basis: %+v", cl)
	}
}
