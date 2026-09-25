package review

import (
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
