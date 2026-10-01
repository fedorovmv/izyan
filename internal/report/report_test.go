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
			!strings.Contains(n, "**рекомендуется исключить**") ||
			!strings.Contains(n, "**исключение не рекомендуется**") ||
			!strings.Contains(n, "x/internal/xds/server.Site") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("all-proposed linked symbols give dismissible pending approval", func(t *testing.T) {
		c := base(`{"ImportPath":"x/internal/transport"}` + "\n" + `{"ImportPath":"x"}`)
		c.Exploit.ProposedNonLocus = append(c.Exploit.ProposedNonLocus,
			domain.LocusDecision{Symbol: sym("x/internal/transport", "B"), Authority: "machine-proposal"})
		if n := machineAssessment(c); !strings.Contains(n, "ОТКЛОНИТЬ ПОСЛЕ ПОДТВЕРЖДЕНИЯ") {
			t.Fatalf("assessment=%q", n)
		}
	})
	t.Run("all locus packages absent is dismissible outright", func(t *testing.T) {
		c := base(`{"ImportPath":"x"}`)
		if n := machineAssessment(c); !strings.Contains(n, "**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ**") {
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

func TestTrackerRationale(t *testing.T) {
	sym := func(pkg, s string) domain.SymbolRef {
		return domain.SymbolRef{Package: pkg, Symbol: s}
	}

	t.Run("no exploit path found renders complete tracker justification", func(t *testing.T) {
		c := &domain.AnalysisCase{
			ID: "case-001",
			Vulnerability: domain.Vulnerability{
				ID:            "CVE-2026-84445",
				Module:        "google.golang.org/grpc",
				Summary:       "паника в xDS routing interceptor при пустом authority",
				FixedVersions: []string{"v1.82.2", "v1.83.2"},
				AffectedPackages: []domain.AffectedPackage{
					{Path: "google.golang.org/grpc/internal/xds"},
					{Path: "google.golang.org/grpc/internal/transport"},
				},
			},
			Product: domain.ProductSnapshot{
				Repository: "example.com/demo-service",
				Commit:     "74224f4d12345678",
				GoVersion:  "1.23.0",
				GOOS:       "linux",
				GOARCH:     "amd64",
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.80.0",
			},
			Exploit: &domain.ExploitModel{
				LocusSubjects: []domain.SymbolRef{
					sym("google.golang.org/grpc/internal/xds", "RouteAndProcess"),
					sym("google.golang.org/grpc/internal/transport", "HandleStreams"),
				},
				NonLocusBasis: []domain.LocusDecision{
					{
						Symbol:    sym("google.golang.org/grpc/internal/transport", "HandleStreams"),
						Authority: "эксперт",
						Basis:     "вспомогательная диспетчеризация, дефектная операция отсутствует",
					},
				},
			},
			EvidenceGraph: domain.EvidenceGraph{
				Evidence: []domain.Evidence{
					{
						Kind:    domain.EvidencePackageList,
						Content: `{"ImportPath":"google.golang.org/grpc/internal/transport"}` + "\n" + `{"ImportPath":"example.com/demo-service"}`,
					},
				},
				Exposures: []domain.ExposureFact{
					{
						CallSite:  domain.CallSite{File: "components/service/consumer.go", Line: 53},
						Direction: "inbound",
						Kind:      "grpc_listener",
						Target:    "google.golang.org/grpc.NewServer",
					},
				},
			},
			Verdict: &domain.VerdictResult{
				Verdict: domain.VerdictNoExploitPathFound,
				Reason:  "mandatory exploit condition is proven false",
			},
		}

		r := TrackerRationale(c)

		// 1. Headline
		if !strings.Contains(r, "Not Exploitable (Уязвимость не эксплуатируется)") {
			t.Fatalf("missing headline: %s", r)
		}
		// 2. Library & Scanner
		if !strings.Contains(r, "google.golang.org/grpc v1.80.0") ||
			!strings.Contains(r, "False Positive") ||
			!strings.Contains(r, "demo-service") {
			t.Fatalf("missing library/scanner context: %s", r)
		}
		// 3. Commit & Snapshot
		if !strings.Contains(r, "74224f4d1234") ||
			!strings.Contains(r, "Go 1.23.0") ||
			!strings.Contains(r, "linux/amd64") {
			t.Fatalf("missing snapshot context: %s", r)
		}
		// 4. Vulnerability mechanism
		if !strings.Contains(r, "CVE-2026-84445") ||
			!strings.Contains(r, "паника в xDS routing interceptor") {
			t.Fatalf("missing defect description: %s", r)
		}
		// 5. Absent package
		if !strings.Contains(r, "google.golang.org/grpc/internal/xds") ||
			!strings.Contains(r, "отсутствуют и в бинарный файл не попадают") {
			t.Fatalf("missing absent packages info: %s", r)
		}
		// 6. Product exposures
		if !strings.Contains(r, "components/service/consumer.go:53") ||
			!strings.Contains(r, "google.golang.org/grpc.NewServer") {
			t.Fatalf("missing exposures info: %s", r)
		}
		// 7. Present package symbols
		if !strings.Contains(r, "HandleStreams") ||
			!strings.Contains(r, "диспетчеризация") {
			t.Fatalf("missing present symbols info: %s", r)
		}
		// 8. Residual risk
		if !strings.Contains(r, "Остаточный риск") ||
			!strings.Contains(r, "v1.82.2") {
			t.Fatalf("missing residual risk or fixed version: %s", r)
		}
		// 9. Tracker closing
		if !strings.Contains(r, "Текст выше можно использовать в задаче трекера как обоснование статуса **Not Exploitable**") {
			t.Fatalf("missing tracker closing: %s", r)
		}
	})

	t.Run("not affected renders outside version range", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:     "CVE-2025-1111",
				Module: "example.com/lib",
			},
			Product: domain.ProductSnapshot{
				Repository: "my-service",
				Commit:     "abc1234",
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimFalse,
				ResolvedVersion: "v2.0.0",
			},
			Verdict: &domain.VerdictResult{
				Verdict: domain.VerdictNotAffected,
				Reason:  "resolved version outside affected range",
			},
		}

		r := TrackerRationale(c)
		if !strings.Contains(r, "Not Affected (Уязвимость не применима к сервису)") ||
			!strings.Contains(r, "v2.0.0") ||
			!strings.Contains(r, "не входит в диапазон уязвимых версий") {
			t.Fatalf("unexpected rationale: %s", r)
		}
	})

	t.Run("exploitable renders remediation required", func(t *testing.T) {
		c := &domain.AnalysisCase{
			Vulnerability: domain.Vulnerability{
				ID:            "CVE-2026-9999",
				Module:        "example.com/bad",
				FixedVersions: []string{"v1.1.0"},
			},
			Product: domain.ProductSnapshot{
				Repository: "vuln-service",
				Commit:     "def5678",
			},
			Affected: &domain.AffectedResult{
				VersionAffected: domain.ClaimTrue,
				ResolvedVersion: "v1.0.0",
			},
			EvidenceGraph: domain.EvidenceGraph{
				Exposures: []domain.ExposureFact{
					{CallSite: domain.CallSite{File: "main.go", Line: 20}, Direction: "inbound", Target: "net/http.ListenAndServe"},
				},
			},
			Verdict: &domain.VerdictResult{
				Verdict: domain.VerdictExploitable,
				Reason:  "all mandatory conditions met",
			},
		}

		r := TrackerRationale(c)
		if !strings.Contains(r, "Exploitable (Уязвимость подтверждена и эксплуатируема)") ||
			!strings.Contains(r, "Требуется исправление") ||
			!strings.Contains(r, "v1.1.0") {
			t.Fatalf("unexpected exploitable rationale: %s", r)
		}
	})
}
