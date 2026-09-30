package goanalysis

import (
	"context"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

var locusTestCond = domain.Condition{
	ID:        "C-LOCUS",
	Kind:      domain.ConditionSymbolReachable,
	Mandatory: true,
	Params:    map[string]string{domain.ParamCheck: domain.CheckLocus},
	Subjects: []domain.SymbolRef{
		{Package: "example.com/lib/internal/xds/server", Symbol: "RouteAndProcess"},
	},
}

func locusTestCase(paths ...string) *domain.AnalysisCase {
	c := &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{}}
	content := ""
	for _, p := range paths {
		content += `{"ImportPath":"` + p + `"}`
	}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID: "EV-PKGS", Kind: domain.EvidencePackageList, Content: content,
	})
	return c
}

func locusFalseClaim() domain.Claim {
	return domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusPackageAbsent,
	}
}

// All locus packages absent from the build graph verifies the falsifier —
// without a source index configured.
func TestVerifyLocusAbsentVerified(t *testing.T) {
	c := locusTestCase("example.com/prod", "example.com/lib/internal/transport")
	out := (Verifier{}).VerifyFalse(context.Background(), c, locusFalseClaim(), locusTestCond)
	if out.NegativeVerification == nil ||
		out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("nv=%+v", out.NegativeVerification)
	}
}

// A locus package present in the graph contradicts the FALSE — the defect
// code is linked, so package absence does not hold.
func TestVerifyLocusAbsentContradicted(t *testing.T) {
	c := locusTestCase("example.com/lib/internal/xds/server")
	out := (Verifier{}).VerifyFalse(context.Background(), c, locusFalseClaim(), locusTestCond)
	if out.NegativeVerification == nil ||
		out.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("nv=%+v", out.NegativeVerification)
	}
}

// Missing package-list evidence leaves the falsifier unverified — a loading
// failure is never absence.
func TestVerifyLocusAbsentNoEvidence(t *testing.T) {
	c := &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{}}
	out := (Verifier{}).VerifyFalse(context.Background(), c, locusFalseClaim(), locusTestCond)
	if out.NegativeVerification == nil ||
		out.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v", out.NegativeVerification)
	}
}
