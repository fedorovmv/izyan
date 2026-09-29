package states

import (
	"context"
	"path/filepath"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/goanalysis"
)

func TestModuleUsageNestedDependencyDoesNotSeedParentReach(t *testing.T) {
	product, err := filepath.Abs(filepath.Join("..", "..", "testdata", "nestedprod"))
	if err != nil {
		t.Fatal(err)
	}
	parent := "example.com/nesteddep"
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			Module: parent,
			AffectedSymbols: []domain.SymbolRef{
				{Package: parent, Symbol: "Parent"},
			},
		},
		Affected: &domain.AffectedResult{SelectedModules: []string{parent}},
	}
	h := CollectEvidence{Source: &goanalysis.Index{Dir: product}}
	h.moduleUsage(context.Background(), c, parent, []string{parent})
	if len(c.EvidenceGraph.ModuleUsages) != 1 || c.EvidenceGraph.ModuleUsages[0].ModuleOwner != parent+"/v2" {
		t.Fatalf("usage sites=%+v, want retained nested-module site", c.EvidenceGraph.ModuleUsages)
	}
	if len(c.EvidenceGraph.ModuleReachable) != 0 {
		t.Fatalf("nested-module call seeded parent reachability: %+v", c.EvidenceGraph.ModuleReachable)
	}
}
