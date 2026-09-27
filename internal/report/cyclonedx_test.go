package report

import (
	"encoding/json"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func cdxCase(verdict domain.Verdict) *domain.AnalysisCase {
	c := &domain.AnalysisCase{
		ID: "TEST-1",
		Vulnerability: domain.Vulnerability{
			ID:     "GHSA-xxxx-yyyy-zzzz",
			Module: "example.com/dep",
		},
		Product: domain.ProductSnapshot{
			Repository: "/tmp/product",
			Commit:     "abc123",
		},
	}
	if verdict != "" {
		c.Verdict = &domain.VerdictResult{Verdict: verdict, Reason: "r"}
	}
	return c
}

func TestCycloneDXMappings(t *testing.T) {
	cases := []struct {
		verdict domain.Verdict
		state   string
		just    string
	}{
		{domain.VerdictExploitable, "exploitable", ""},
		{domain.VerdictNotAffected, "not_affected", "code_not_present"},
		{domain.VerdictNoExploitPathFound, "not_affected", "code_not_reachable"},
		{domain.VerdictInconclusive, "in_triage", ""},
	}
	for _, tc := range cases {
		b, err := CycloneDX(cdxCase(tc.verdict))
		if err != nil {
			t.Fatalf("%s: %v", tc.verdict, err)
		}
		var doc struct {
			BOMFormat       string `json:"bomFormat"`
			SpecVersion     string `json:"specVersion"`
			Vulnerabilities []struct {
				ID       string `json:"id"`
				Analysis struct {
					State         string `json:"state"`
					Justification string `json:"justification"`
				} `json:"analysis"`
			} `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: invalid json: %v", tc.verdict, err)
		}
		if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.5" {
			t.Fatalf("%s: bad envelope: %+v", tc.verdict, doc)
		}
		v := doc.Vulnerabilities[0]
		if v.Analysis.State != tc.state || v.Analysis.Justification != tc.just {
			t.Fatalf("%s: analysis=%+v want state=%s just=%s",
				tc.verdict, v.Analysis, tc.state, tc.just)
		}
	}
}

func TestCycloneDXWrite(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, cdxCase(domain.VerdictInconclusive)); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"report.json", "report.md", "openvex.json", "cyclonedx.json"} {
		if !strings.Contains(f, ".") {
			t.Fatal("unreachable")
		}
	}
}
