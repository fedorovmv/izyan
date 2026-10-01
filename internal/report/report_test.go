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

func TestMachineAssessment(t *testing.T) {
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
					{Symbol: sym("x/internal/transport", "A"), Authority: "machine-proposal", Basis: "enabler-candidate"},
				},
				LocusAnnotations: []domain.LocusDecision{
					{Symbol: sym("x/internal/transport", "B"), Authority: "machine-annotation", Basis: "guarded-site; fix hunk guards the faulting operation"},
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
	t.Run("linked packages split proposals from flagged symbols", func(t *testing.T) {
		c := base(`{"ImportPath":"x/internal/transport"}` + "\n" + `{"ImportPath":"x"}`)
		n := machineAssessment(c)
		if !strings.Contains(n, "УСЛОВНО") ||
			!strings.Contains(n, "**предлагает**") ||
			!strings.Contains(n, "**не предлагается**") ||
			!strings.Contains(n, "x/internal/xds/server.Site") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("all-proposed linked symbols give dismissible pending approval", func(t *testing.T) {
		c := base(`{"ImportPath":"x/internal/transport"}` + "\n" + `{"ImportPath":"x"}`)
		c.Exploit.ProposedNonLocus = append(c.Exploit.ProposedNonLocus,
			domain.LocusDecision{Symbol: sym("x/internal/transport", "B"), Authority: "machine-proposal"})
		if n := machineAssessment(c); !strings.Contains(n, "ОТКЛОНИТЬ после утверждения") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("all locus packages absent is dismissible outright", func(t *testing.T) {
		c := base(`{"ImportPath":"x"}`)
		if n := machineAssessment(c); !strings.Contains(n, "**Предлагаемая оценка: ОТКЛОНИТЬ**") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("missing package-list evidence cannot be assessed", func(t *testing.T) {
		c := base("")
		c.EvidenceGraph.Evidence = nil
		if n := machineAssessment(c); !strings.Contains(n, "нельзя") {
			t.Fatalf("assessment=%q", n)
		}
	})
}
