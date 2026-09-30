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

func TestProposedFalsifierNoteAllAbsent(t *testing.T) {
	sym := func(pkg, s string) domain.SymbolRef {
		return domain.SymbolRef{Package: pkg, Symbol: s}
	}
	base := func(content string) *domain.AnalysisCase {
		return &domain.AnalysisCase{
			Exploit: &domain.ExploitModel{
				LocusSubjects: []domain.SymbolRef{
					sym("x/internal/transport", "A"),
					sym("x/internal/transport", "B"),
					sym("x/internal/xds/server", "Site"),
				},
				ProposedNonLocus: []domain.LocusDecision{
					{Symbol: sym("x/internal/transport", "A"), Authority: "machine-proposal"},
					{Symbol: sym("x/internal/transport", "B"), Authority: "machine-proposal"},
				},
			},
			EvidenceGraph: domain.EvidenceGraph{
				Evidence: []domain.Evidence{{
					Kind:    domain.EvidencePackageList,
					Content: content,
				}},
			},
		}
	}
	t.Run("remaining package absent produces note", func(t *testing.T) {
		c := base(`{"ImportPath":"x/internal/transport"}` + "\n" + `{"ImportPath":"x"}`)
		if n := proposedFalsifierNote(c); !strings.Contains(n, "NO_EXPLOIT_PATH_FOUND") {
			t.Fatalf("note=%q", n)
		}
	})
	t.Run("remaining package linked reports falsifier would not hold", func(t *testing.T) {
		c := base(`{"ImportPath":"x/internal/transport"}` + "\n" + `{"ImportPath":"x/internal/xds/server"}`)
		n := proposedFalsifierNote(c)
		if !strings.Contains(n, "would **not** hold") || !strings.Contains(n, "x/internal/xds/server.Site") {
			t.Fatalf("note=%q", n)
		}
	})
	t.Run("missing package-list evidence yields no note", func(t *testing.T) {
		c := base("")
		c.EvidenceGraph.Evidence = nil
		if n := proposedFalsifierNote(c); n != "" {
			t.Fatalf("note=%q", n)
		}
	})
	t.Run("no proposals yields no note", func(t *testing.T) {
		c := base(`{"ImportPath":"x"}`)
		c.Exploit.ProposedNonLocus = nil
		if n := proposedFalsifierNote(c); n != "" {
			t.Fatalf("note=%q", n)
		}
	})
}
