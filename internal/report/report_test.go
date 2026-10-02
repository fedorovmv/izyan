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

func TestMarkdownStructureInvertedPyramid(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-report-test",
		Vulnerability: domain.Vulnerability{
			ID:            "GO-2026-6443",
			Module:        "example.com/mod",
			FixedVersions: []string{"v1.2.0"},
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product",
			Commit:     "abc12345",
			GoVersion:  "go1.26.1",
			GOOS:       "darwin",
			GOARCH:     "arm64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
		},
		Exploit: &domain.ExploitModel{
			Class:  "RESOURCE_EXHAUSTION",
			Impact: "Server panic (DoS)",
		},
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{
				{Origin: domain.OriginInternalService, Summary: "test dataflow"},
			},
			ToolExecutions: []domain.ToolExecution{
				{Tool: "go", Args: []string{"version"}, ExitCode: 0, DurationMs: 10, StdoutSHA256: "abcdef1234567890"},
			},
		},
	}

	md := Markdown(c)

	// Ensure sections appear in the exact required order:
	idxHeader := strings.Index(md, "# Vulnerability analysis: GO-2026-6443")
	idxVerdict := strings.Index(md, "## Verdict: `NO_EXPLOIT_PATH_FOUND`")
	idxVerdictBlockquote := strings.Index(md, "> **mandatory exploit condition is proven false**")
	idxRationale := strings.Index(md, "## Резюме для трекера (Tracker-ready rationale)")
	idxRemediation := strings.Index(md, "## Рекомендации по устранению (Remediation)")
	idxEvidence := strings.Index(md, "## Доказательная база (Evidence & Claims)")
	idxDetailsOpen := strings.Index(md, "<details>")
	idxDetailsSummary := strings.Index(md, "<summary><b>Технические детали и аудит (Data Flows, Tool Executions, Limitations)</b></summary>")
	idxDataFlows := strings.Index(md, "### Потоки данных (Data Flows)")
	idxToolExec := strings.Index(md, "### Журнал инструментов (Tool Executions)")
	idxDetailsClose := strings.Index(md, "</details>")

	if idxHeader == -1 || idxVerdict == -1 || idxVerdictBlockquote == -1 || idxRationale == -1 || idxRemediation == -1 ||
		idxEvidence == -1 || idxDetailsOpen == -1 || idxDetailsSummary == -1 || idxDataFlows == -1 || idxToolExec == -1 || idxDetailsClose == -1 {
		t.Fatalf("one or more expected sections missing from Markdown output:\n%s", md)
	}

	if !(idxHeader < idxVerdict &&
		idxVerdict < idxVerdictBlockquote &&
		idxVerdictBlockquote < idxRationale &&
		idxRationale < idxRemediation &&
		idxRemediation < idxEvidence &&
		idxEvidence < idxDetailsOpen &&
		idxDetailsOpen < idxDetailsSummary &&
		idxDetailsSummary < idxDataFlows &&
		idxDataFlows < idxToolExec &&
		idxToolExec < idxDetailsClose) {
		t.Fatalf("sections are not in inverted pyramid order. Indices:\nheader=%d, verdict=%d, quote=%d, rationale=%d, remediation=%d, evidence=%d, detailsOpen=%d, summary=%d, dataFlows=%d, toolExec=%d, detailsClose=%d",
			idxHeader, idxVerdict, idxVerdictBlockquote, idxRationale, idxRemediation, idxEvidence, idxDetailsOpen, idxDetailsSummary, idxDataFlows, idxToolExec, idxDetailsClose)
	}
}

func TestMarkdownStructureInvertedPyramid_FullSections(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-report-full",
		Vulnerability: domain.Vulnerability{
			ID:            "CVE-2026-12345",
			Module:        "example.com/mod",
			FixedVersions: []string{"v1.2.0"},
			AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/mod/vulnpkg"},
			},
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product",
			Commit:     "1234567890ab",
			GoVersion:  "go1.26.1",
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		Affected: &domain.AffectedResult{
			VersionAffected: domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			ModulePresent:   domain.ClaimTrue,
			PackagePresent:  domain.ClaimFalse,
			Limitations:     []string{"affected limitation 1"},
		},
		Claims: []domain.Claim{
			{ConditionID: "C-LOCUS", Result: domain.ClaimFalse},
		},
		RootCause: &domain.RootCauseModel{
			Status: domain.RootCauseResolved,
			RootCauses: []domain.RootCause{
				{Package: "example.com/mod/vulnpkg", Symbol: "VulnFunc", Role: domain.RootCauseSink, Mechanism: "out-of-bounds read"},
			},
		},
		Exploit: &domain.ExploitModel{
			Class:  "MEMORY_CORRUPTION",
			Impact: "Remote Code Execution",
			MandatoryConditions: []domain.Condition{
				{ID: "C-LOCUS", Kind: "code", Description: "vulnerable function called"},
			},
			SupportingFactors: []domain.Condition{
				{ID: "C-INPUT", Kind: "input", Description: "untrusted input provided"},
			},
			NonLocusBasis: []domain.LocusDecision{
				{Symbol: domain.SymbolRef{Package: "example.com/mod/vulnpkg", Symbol: "SafeFunc"}, Authority: "expert", Basis: "safe helper"},
			},
		},
		EvidenceGraph: domain.EvidenceGraph{
			Exposures: []domain.ExposureFact{
				{CallSite: domain.CallSite{File: "main.go", Line: 42}, Direction: "inbound", Target: "net/http.ListenAndServe"},
			},
			DataFlows: []domain.DataFlow{
				{Origin: domain.OriginExternalUntrusted, Summary: "query param flows to sink"},
			},
			ToolExecutions: []domain.ToolExecution{
				{Tool: "govulncheck", Args: []string{"./..."}, ExitCode: 0, DurationMs: 150, StdoutSHA256: "fedcba0987654321"},
			},
			Runtime: []domain.EvidenceID{"EV-RUNTIME-1"},
			Evidence: []domain.Evidence{
				{ID: "EV-RUNTIME-1", Kind: domain.EvidenceRuntime, Source: "runtime-env", Content: "go version go1.26.1"},
				{ID: "EV-BUILD-1", Kind: domain.EvidenceBuild, Source: "go build", Content: "build successful\nall targets ok"},
			},
			Limitations: []string{"graph limitation 1"},
		},
		Hypotheses: []domain.Hypothesis{
			{ID: "H-1", ConditionID: "C-LOCUS", Status: domain.HypothesisRejected, Statement: "package not linked"},
		},
		Reviews: []domain.Review{
			{
				ID:     "REV-1",
				Result: domain.ReviewAccept,
				Findings: []domain.ReviewFinding{
					{Severity: "LOW", TargetType: "claim", TargetID: "C-LOCUS", Problem: "minor verification note"},
				},
			},
		},
	}

	md := Markdown(c)

	expectedSectionsInOrder := []string{
		"# Vulnerability analysis: CVE-2026-12345",
		"## Verdict: `NO_EXPLOIT_PATH_FOUND`",
		"> **mandatory exploit condition is proven false**",
		"## Резюме для трекера (Tracker-ready rationale)",
		"## Рекомендации по устранению (Remediation)",
		"## Доказательная база (Evidence & Claims)",
		"### Применимость (Affected Analysis)",
		"### Статус условий эксплуатации (Claims)",
		"### Точки входа (Exposure Facts)",
		"### Модель эксплуатации и сайты дефекта (Exploit & Locus)",
		"<details>",
		"<summary><b>Технические детали и аудит (Data Flows, Tool Executions, Limitations)</b></summary>",
		"### Потоки данных (Data Flows)",
		"### Журнал инструментов (Tool Executions)",
		"### Ограничения анализа (Limitations)",
		"### Рецензирование (Review Findings)",
		"### Факты среды (Runtime Facts)",
		"### Сборка и тесты (Build & Test)",
		"### Гипотезы (Hypotheses)",
		"</details>",
	}

	lastIdx := -1
	for _, sec := range expectedSectionsInOrder {
		idx := strings.Index(md, sec)
		if idx == -1 {
			t.Fatalf("expected section %q not found in Markdown output:\n%s", sec, md)
		}
		if idx <= lastIdx {
			t.Fatalf("section %q at index %d is out of order (previous at %d)", sec, idx, lastIdx)
		}
		lastIdx = idx
	}
}
