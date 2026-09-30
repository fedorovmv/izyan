package evaluator

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

var locusCond = domain.Condition{
	ID:        "C-LOCUS",
	Kind:      domain.ConditionSymbolReachable,
	Mandatory: true,
	Params:    map[string]string{domain.ParamCheck: domain.CheckLocus},
	Subjects: []domain.SymbolRef{
		{Package: "example.com/lib/internal/xds/server", Symbol: "RouteAndProcess"},
	},
}

func caseWithPackages(paths ...string) *domain.AnalysisCase {
	c := &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{}}
	content := ""
	for _, p := range paths {
		content += `{"ImportPath":"` + p + `"}`
	}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID:      "EV-PKGS",
		Kind:    domain.EvidencePackageList,
		Content: content,
	})
	return c
}

// Every locus package absent from the build graph grounds the FALSE
// candidate with the locus-package-absent falsifier.
func TestEvalLocusAbsentFalsifier(t *testing.T) {
	c := caseWithPackages("example.com/lib/internal/transport", "example.com/prod")
	claim := (SymbolReachable{}).Evaluate(locusCond, c)
	if claim.Result != domain.ClaimFalse || claim.Falsifier != domain.FalsifierLocusPackageAbsent {
		t.Fatalf("claim=%+v", claim)
	}
	if len(claim.EvidenceIDs) != 1 || claim.EvidenceIDs[0] != "EV-PKGS" {
		t.Fatalf("evidence=%v", claim.EvidenceIDs)
	}
}

// A locus package linked into the graph is a different, unproven claim —
// package presence cannot be argued away by call-path silence.
func TestEvalLocusPackagePresentUnknown(t *testing.T) {
	c := caseWithPackages("example.com/lib/internal/xds/server", "example.com/prod")
	claim := (SymbolReachable{}).Evaluate(locusCond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("expected UNKNOWN, got %+v", claim)
	}
}

// No package-list evidence, no FALSE: a missing build graph is UNKNOWN, not
// absence.
func TestEvalLocusNoPackageListUnknown(t *testing.T) {
	c := &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{}}
	claim := (SymbolReachable{}).Evaluate(locusCond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("expected UNKNOWN, got %+v", claim)
	}
}

// Undecodable package-list evidence is equally UNKNOWN.
func TestEvalLocusCorruptPackageListUnknown(t *testing.T) {
	c := &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{}}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID: "EV-PKGS", Kind: domain.EvidencePackageList, Content: `{garbage`,
	})
	claim := (SymbolReachable{}).Evaluate(locusCond, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("expected UNKNOWN, got %+v", claim)
	}
}

// Two independent defect sites in one advisory: L spans two packages and
// only one is absent from the build graph — the falsifier cannot cover the
// surviving site, so the claim stays UNKNOWN and no NEPF is possible.
func TestEvalLocusTwoDefectsPartialCoverage(t *testing.T) {
	twoLocus := domain.Condition{
		ID:        "C-LOCUS",
		Kind:      domain.ConditionSymbolReachable,
		Mandatory: true,
		Params:    map[string]string{domain.ParamCheck: domain.CheckLocus},
		Subjects: []domain.SymbolRef{
			{Package: "example.com/lib/internal/xds/server", Symbol: "RouteAndProcess"},
			{Package: "example.com/lib/internal/transport", Symbol: "http2Server.legacyRoute"},
		},
	}
	c := caseWithPackages("example.com/lib/internal/transport", "example.com/prod")
	claim := (SymbolReachable{}).Evaluate(twoLocus, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("partial package coverage must stay UNKNOWN, got %+v", claim)
	}
}

// A govulncheck call path reaching a locus subject is a TRUE — mode-on and
// wrapper variants cannot be argued away by package semantics.
func TestEvalLocusCallPathTrue(t *testing.T) {
	c := caseWithPackages("example.com/lib/internal/xds/server")
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID: "EV-GV", Kind: domain.EvidenceGovulncheck, Content: "ran",
	})
	c.EvidenceGraph.CallPaths = append(c.EvidenceGraph.CallPaths, domain.CallPath{
		EvidenceID: "EV-GV",
		Frames: []domain.CallSite{
			{Package: "example.com/prod", Function: "main"},
			{Package: "example.com/lib/internal/xds/server", Function: "RouteAndProcess"},
		},
	})
	claim := (SymbolReachable{}).Evaluate(locusCond, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("expected TRUE, got %+v", claim)
	}
}
