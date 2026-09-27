package review

import (
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func baseCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		RootCause: &domain.RootCauseModel{
			Status:     domain.RootCauseResolved,
			RootCauses: []domain.RootCause{{Package: "example.com/dep", Symbol: "vuln.Parse"}},
		},
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{ID: "C-1", Kind: domain.ConditionSymbolReachable}},
		},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{{ID: "EV-1", Kind: domain.EvidenceGovulncheck}},
		},
	}
}

func TestReviewAcceptsCleanCase(t *testing.T) {
	c := baseCase()
	c.Claims = []domain.Claim{{
		ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue,
		EvidenceIDs: []domain.EvidenceID{"EV-1"},
	}}
	r := Structural{}.Review(c, domain.VerdictResult{Verdict: domain.VerdictExploitable})
	if r.Result != domain.ReviewAccept {
		t.Fatalf("result = %s, findings: %+v", r.Result, r.Findings)
	}
}

func TestReviewRejectsUnsupportedTrue(t *testing.T) {
	c := baseCase()
	c.Claims = []domain.Claim{{ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue}}
	r := Structural{}.Review(c, domain.VerdictResult{Verdict: domain.VerdictExploitable})
	if r.Result != domain.ReviewRevise {
		t.Fatalf("result = %s, want REVISE", r.Result)
	}
	found := false
	for _, f := range r.Findings {
		if f.TargetType == "claim" && f.TargetID == "CL-1" && f.Severity == "high" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no high-severity claim finding: %+v", r.Findings)
	}
}

func TestReviewRejectsFalseWithoutVerification(t *testing.T) {
	c := baseCase()
	c.Claims = []domain.Claim{{
		ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimFalse,
		EvidenceIDs: []domain.EvidenceID{"EV-1"},
	}}
	r := Structural{}.Review(c, domain.VerdictResult{Verdict: domain.VerdictNoExploitPathFound})
	if r.Result != domain.ReviewRevise {
		t.Fatalf("result = %s, want REVISE", r.Result)
	}
}

func TestReviewAcceptsVerifiedFalse(t *testing.T) {
	c := baseCase()
	c.Claims = []domain.Claim{{
		ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimFalse,
		EvidenceIDs: []domain.EvidenceID{"EV-1"},
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeVerified, EvidenceIDs: []domain.EvidenceID{"EV-1"},
		},
	}}
	r := Structural{}.Review(c, domain.VerdictResult{Verdict: domain.VerdictNoExploitPathFound})
	if r.Result != domain.ReviewAccept {
		t.Fatalf("result = %s: %+v", r.Result, r.Findings)
	}
}

func TestReviewFlagsContradictedFalse(t *testing.T) {
	c := baseCase()
	c.Claims = []domain.Claim{{
		ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimFalse,
		EvidenceIDs: []domain.EvidenceID{"EV-1"},
		NegativeVerification: &domain.NegativeVerification{
			Status: domain.NegativeContradicted, EvidenceIDs: []domain.EvidenceID{"EV-1"},
		},
	}}
	r := Structural{}.Review(c, domain.VerdictResult{Verdict: domain.VerdictNoExploitPathFound})
	if r.Result != domain.ReviewRevise {
		t.Fatalf("result = %s, want REVISE", r.Result)
	}
}

func TestReviewFlagsDanglingEvidence(t *testing.T) {
	c := baseCase()
	c.Claims = []domain.Claim{{
		ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue,
		EvidenceIDs: []domain.EvidenceID{"EV-GHOST"},
	}}
	r := Structural{}.Review(c, domain.VerdictResult{Verdict: domain.VerdictExploitable})
	if r.Result != domain.ReviewRevise {
		t.Fatalf("result = %s, want REVISE", r.Result)
	}
}

func TestReviewNotesToolLimitationsOnStrongVerdict(t *testing.T) {
	c := baseCase()
	c.Claims = []domain.Claim{{
		ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue,
		EvidenceIDs: []domain.EvidenceID{"EV-1"},
	}}
	c.EvidenceGraph.ToolLimitations = []string{"govulncheck timed out"}
	r := Structural{}.Review(c, domain.VerdictResult{Verdict: domain.VerdictExploitable})
	if r.Result != domain.ReviewAccept {
		t.Fatalf("medium findings must not trigger REVISE: %+v", r.Findings)
	}
	seen := false
	for _, f := range r.Findings {
		if f.TargetType == "verdict" {
			seen = true
		}
	}
	if !seen {
		t.Fatal("expected verdict-level finding about tool limitations")
	}
}

func TestStructuralPatternCoverage(t *testing.T) {
	mkCase := func(conds []domain.Condition, lims []string) *domain.AnalysisCase {
		return &domain.AnalysisCase{
			Exploit: &domain.ExploitModel{
				Class:               "WIRE_PARSER",
				RootCauses:          []domain.SymbolRef{{Package: "p", Symbol: "Parse"}},
				MandatoryConditions: conds,
			},
			RootCause: &domain.RootCauseModel{},
		}
	}
	// Dropped conditions (no skip limitation) -> high findings -> REVISE.
	c := mkCase([]domain.Condition{
		{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true},
	}, nil)
	r := Structural{}.Review(c, domain.VerdictResult{})
	var highs int
	for _, f := range r.Findings {
		if f.TargetType == "model" && f.Severity == "high" &&
			strings.Contains(f.Problem, "pattern expects") {
			highs++
		}
	}
	if highs != 2 {
		t.Fatalf("expected 2 high findings for C-PEER-INPUT/C-CONSTRAINT, got %+v", r.Findings)
	}
	if r.Result != domain.ReviewRevise {
		t.Fatalf("result=%s want REVISE", r.Result)
	}

	// A recorded bind skip downgrades the finding to medium.
	c2 := mkCase([]domain.Condition{
		{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true},
		{ID: "C-PEER-INPUT", Kind: domain.ConditionAttackerControl, Mandatory: true},
		{ID: "C-CONSTRAINT", Kind: domain.ConditionInputConstraint, Mandatory: true},
	}, nil)
	r2 := Structural{}.Review(c2, domain.VerdictResult{})
	for _, f := range r2.Findings {
		if strings.Contains(f.Problem, "pattern expects") {
			t.Fatalf("complete model must not be flagged: %+v", f)
		}
	}
}

func TestStructuralPatchAndScopeChecks(t *testing.T) {
	// Patch misinterpretation: fix diff exists but names no RC symbol.
	c := baseCase()
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID: "EV-D", Kind: domain.EvidenceFixDiff, Content: "diff --git a/x.go\n-func other() {}",
	})
	r := Structural{}.Review(c, domain.VerdictResult{})
	var sawPatch bool
	for _, f := range r.Findings {
		if strings.Contains(f.Problem, "patch misinterpretation") {
			sawPatch = true
		}
	}
	if !sawPatch {
		t.Fatal("patch misinterpretation finding expected")
	}

	// Same diff naming the RC symbol -> clean.
	c2 := baseCase()
	c2.EvidenceGraph.Evidence = append(c2.EvidenceGraph.Evidence, domain.Evidence{
		ID: "EV-D", Kind: domain.EvidenceFixDiff, Content: "-func Parse(s string) {",
	})
	r2 := Structural{}.Review(c2, domain.VerdictResult{})
	for _, f := range r2.Findings {
		if strings.Contains(f.Problem, "patch misinterpretation") {
			t.Fatal("false positive patch finding")
		}
	}

	// Scope mismatch: source evidence outside the product tree.
	c3 := baseCase()
	c3.Product.Repository = "/tmp/prod"
	c3.EvidenceGraph.Evidence = append(c3.EvidenceGraph.Evidence, domain.Evidence{
		ID: "EV-X", Kind: domain.EvidenceSourceSnippet, File: "/elsewhere/x.go",
	})
	r3 := Structural{}.Review(c3, domain.VerdictResult{})
	var sawScope bool
	for _, f := range r3.Findings {
		if strings.Contains(f.Problem, "outside analyzed scope") {
			sawScope = true
		}
	}
	if !sawScope {
		t.Fatal("scope mismatch finding expected")
	}
}
