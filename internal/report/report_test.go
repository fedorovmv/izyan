package report

import (
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestRemediationPicksMinFixAboveResolved(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:            "GO-X",
			Module:        "example.com/mod",
			FixedVersions: []string{"v1.5.0", "v1.4.0", "v2.0.0"},
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.4.0",
		},
	}
	r := remediation(c)
	if !strings.Contains(r, "v1.5.0") || !strings.Contains(r, "go get example.com/mod@v1.5.0") {
		t.Fatalf("remediation=%q", r)
	}
}

func TestRemediationEmptyWhenNotAffected(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "m", FixedVersions: []string{"v1.0.0"}},
		Affected:      &domain.AffectedResult{VersionAffected: domain.ClaimFalse},
	}
	if remediation(c) != "" {
		t.Fatal("no remediation expected when not affected")
	}
}

func TestRemediationNoFixPublished(t *testing.T) {
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "m"},
		Affected:      &domain.AffectedResult{VersionAffected: domain.ClaimTrue, ResolvedVersion: "v9.9.9"},
	}
	if !strings.Contains(remediation(c), "No fixed version") {
		t.Fatal("expected no-fix message")
	}
}
