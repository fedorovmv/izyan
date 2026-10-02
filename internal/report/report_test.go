package report

import (
	"os"
	"path/filepath"
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
	idxHeader := strings.Index(md, "# Анализ уязвимости: GO-2026-6443")
	idxVerdict := strings.Index(md, "## Вердикт: `NO_EXPLOIT_PATH_FOUND`")
	idxVerdictBlockquote := strings.Index(md, "> **Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)**")
	idxRationale := strings.Index(md, "## Резюме")
	idxRemediation := strings.Index(md, "## Рекомендации по устранению")
	idxEvidence := strings.Index(md, "## Доказательная база")
	idxAudit := strings.Index(md, "## Технические детали и аудит (Data Flows, Tool Executions, Limitations)")
	idxDataFlows := strings.Index(md, "### Потоки данных (Data Flows)")
	idxToolExec := strings.Index(md, "### Журнал инструментов (Tool Executions)")

	if idxHeader == -1 || idxVerdict == -1 || idxVerdictBlockquote == -1 || idxRationale == -1 || idxRemediation == -1 ||
		idxEvidence == -1 || idxAudit == -1 || idxDataFlows == -1 || idxToolExec == -1 {
		t.Fatalf("one or more expected sections missing from Markdown output:\n%s", md)
	}

	if !(idxHeader < idxVerdict &&
		idxVerdict < idxVerdictBlockquote &&
		idxVerdictBlockquote < idxRationale &&
		idxRationale < idxRemediation &&
		idxRemediation < idxEvidence &&
		idxEvidence < idxAudit &&
		idxAudit < idxDataFlows &&
		idxDataFlows < idxToolExec) {
		t.Fatalf("sections are not in inverted pyramid order. Indices:\nheader=%d, verdict=%d, quote=%d, rationale=%d, remediation=%d, evidence=%d, audit=%d, dataFlows=%d, toolExec=%d",
			idxHeader, idxVerdict, idxVerdictBlockquote, idxRationale, idxRemediation, idxEvidence, idxAudit, idxDataFlows, idxToolExec)
	}
	if strings.Contains(md, "<details>") || strings.Contains(md, "<summary>") {
		t.Fatalf("markdown should not contain <details> or <summary> tags")
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
		"# Анализ уязвимости: CVE-2026-12345",
		"## Вердикт: `NO_EXPLOIT_PATH_FOUND`",
		"> **Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)**",
		"## Резюме",
		"## Рекомендации по устранению",
		"## Доказательная база",
		"### Источники и методы проверки (Методология)",
		"### Применимость (Affected Analysis)",
		"### Статус условий эксплуатации (Claims)",
		"### Точки входа (Exposure Facts)",
		"### Модель эксплуатации и сайты дефекта",
		"## Технические детали и аудит (Data Flows, Tool Executions, Limitations)",
		"### Потоки данных (Data Flows)",
		"### Журнал инструментов (Tool Executions)",
		"### Ограничения анализа (Limitations)",
		"### Рецензирование (Review Findings)",
		"### Факты среды (Runtime Facts)",
		"### Сборка и тесты (Build & Test)",
		"### Рабочие гипотезы (Hypotheses)",
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

func sampleCaseForLocalization() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		ID: "case-loc-test",
		Vulnerability: domain.Vulnerability{
			ID:            "GO-2026-6443",
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
			BuildRelevant:   domain.ClaimTrue,
			CheckedModules:  []string{"example.com/mod"},
			SelectedModules: []string{"example.com/mod"},
			PendingModules:  []string{"example.com/pending"},
			CheckedPackages: []string{"example.com/mod/vulnpkg"},
			EvidenceIDs:     []domain.EvidenceID{"EV-AFF-1"},
			Limitations:     []string{"affected limitation"},
		},
		Claims: []domain.Claim{
			{
				ConditionID: "C-LOCUS",
				Result:      domain.ClaimFalse,
				Falsifier:   "locus-package-absent",
				NegativeVerification: &domain.NegativeVerification{
					Status: domain.NegativeVerified,
				},
				EvidenceIDs: []domain.EvidenceID{"EV-CLM-1"},
			},
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
				{ID: "C-REACH", Kind: "code", Description: "symbol reachable"},
				{ID: "C-PEER-INPUT", Kind: "input", Description: "peer input controlled"},
				{ID: "C-CONSTRAINT", Kind: "constraint", Description: "constraint violation"},
			},
			SupportingFactors: []domain.Condition{
				{ID: "C-EXPOSURE", Kind: "network", Description: "network reachable"},
				{ID: "C-TLS-VERIFY", Kind: "tls", Description: "tls verify disabled"},
			},
			NonLocusBasis: []domain.LocusDecision{
				{Symbol: domain.SymbolRef{Package: "example.com/mod/vulnpkg", Symbol: "SafeFunc"}, Authority: "эксперт", Basis: "safe helper"},
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
}

func TestMarkdownLocalizationRU(t *testing.T) {
	c := sampleCaseForLocalization()

	for _, md := range []string{Markdown(c, "ru"), Markdown(c)} { // both explicit "ru" and default
		expectedPhrases := []string{
			"# Анализ уязвимости: GO-2026-6443",
			"- Кейс: `case-loc-test`",
			"- Репозиторий: `example.com/product`",
			"- Коммит: `1234567890ab`",
			"- Окружение Go: `go1.26.1` (linux/amd64)",
			"## Вердикт: `NO_EXPLOIT_PATH_FOUND`",
			"> **Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)**",
			"## Резюме",
			"## Рекомендации по устранению",
			"Обновите зависимость `example.com/mod` с `v1.0.0` до `v1.2.0`:",
			"## Доказательная база",
			"### Применимость (Affected Analysis)",
			"| Проверка | Результат |",
			"| Наличие модуля в зависимостях |",
			"| Разрешённая версия в go.mod |",
			"| Версия входит в диапазон уязвимых |",
			"| Уязвимый пакет входит в сборку |",
			"| Код компилируется для целевой платформы |",
			"| Проверенные модули |",
			"| Скомпилированные модули |",
			"| Модули с неопределённой версией |",
			"| Проверенные пакеты |",
			"| Идентификаторы доказательств (Evidence IDs) |",
			"### Статус условий эксплуатации (Claims)",
			"| Условие | Результат | Верификация | Доказательства |",
			"Пакет отсутствует в сборке / ПОДТВЕРЖДЕНО",
			"### Точки входа (Exposure Facts)",
			"Входящий слушатель через `net/http.ListenAndServe`",
			"### Модель эксплуатации и сайты дефекта",
			"#### Первопричина дефекта (Root cause): Определена",
			"VulnFunc` (Точка сбоя / Sink)",
			"Класс дефекта: `MEMORY_CORRUPTION`",
			"Последствия: Remote Code Execution",
			"#### Обязательные условия (Mandatory conditions)",
			"Выполнение уязвимого кода: пакеты дефектного кода входят в граф сборки приложения",
			"Достижимость символов: хотя бы одна из уязвимых функций вызывается в коде продукта",
			"Контроль ввода: параметры уязвимой функции контролируются удалённым клиентом",
			"Нарушение ограничений: удалённый клиент может передать входные данные, вызывающие сбой",
			"#### Сопутствующие факторы (Supporting factors)",
			"Сетевая доступность: наличие открытых сетевых портов или исходящих подключений",
			"Проверка TLS: отключение проверки сертификатов позволяет передавать трафик без доверенного канала",
			"### Источники и методы проверки (Методология)",
			"| Статический анализ вызовов (govulncheck) |",
			"#### Функции без дефекта (исключены из анализа уязвимости)",
			"## Технические детали и аудит (Data Flows, Tool Executions, Limitations)",
			"### Потоки данных (Data Flows)",
			"### Журнал инструментов (Tool Executions)",
			"| Инструмент | Аргументы | Код возврата | Длительность (мс) | SHA-256 вывода |",
			"### Ограничения анализа (Limitations)",
			"### Рецензирование (Review Findings)",
			"### Факты среды (Runtime Facts)",
			"### Сборка и тесты (Build & Test)",
			"### Рабочие гипотезы (Hypotheses)",
		}

		for _, phrase := range expectedPhrases {
			if !strings.Contains(md, phrase) {
				t.Errorf("RU markdown missing expected phrase: %q", phrase)
			}
		}

		if strings.Contains(md, "<details>") || strings.Contains(md, "<summary>") {
			t.Errorf("RU markdown should not contain <details> or <summary> tags")
		}
		if strings.Contains(md, "# Vulnerability analysis:") {
			t.Errorf("RU markdown should not contain English header '# Vulnerability analysis:'")
		}
		if strings.Contains(md, "## Резюме для трекера (Tracker-ready rationale)") {
			t.Errorf("RU markdown should use strictly '## Резюме', not old verbose header")
		}
	}
}

func TestMarkdownLocalizationEN(t *testing.T) {
	c := sampleCaseForLocalization()
	md := Markdown(c, "en")

	expectedPhrases := []string{
		"# Vulnerability analysis: GO-2026-6443",
		"- Case: `case-loc-test`",
		"- Repository: `example.com/product`",
		"- Commit: `1234567890ab`",
		"- Go: `go1.26.1` (linux/amd64)",
		"## Verdict: `NO_EXPLOIT_PATH_FOUND`",
		"> **mandatory exploit condition is proven false**",
		"## Executive Summary",
		"## Remediation",
		"Update `example.com/mod` from `v1.0.0` to `v1.2.0`:",
		"## Evidence Dossier",
		"### Verification Sources & Methods (Methodology)",
		"### Affected Analysis",
		"| check | result |",
		"| module present |",
		"| package present |",
		"| static call analysis (govulncheck) |",
		"### Claims Status",
		"| condition | result | verification | evidence |",
		"locus-package-absent / VERIFIED",
		"### Exposure Facts",
		"`inbound`",
		"### Exploit Model & Defect Locus",
		"#### Root cause: `RESOLVED`",
		"Class: `MEMORY_CORRUPTION`",
		"Impact: Remote Code Execution",
		"#### Mandatory conditions",
		"#### Supporting factors",
		"## Technical Details & Audit (Data Flows, Tool Executions, Limitations)",
		"### Data Flows",
		"### Tool Executions",
		"| tool | args | exit | ms | stdout sha256 |",
		"### Limitations",
		"### Review Findings",
		"### Runtime Facts",
		"### Build & Test",
		"### Hypotheses",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(md, phrase) {
			t.Errorf("EN markdown missing expected phrase: %q", phrase)
		}
	}

	if strings.Contains(md, "<details>") || strings.Contains(md, "<summary>") {
		t.Errorf("EN markdown should not contain <details> or <summary> tags")
	}
	if strings.Contains(md, "# Анализ уязвимости:") {
		t.Errorf("EN markdown should not contain Russian header '# Анализ уязвимости:'")
	}
	if strings.Contains(md, "## Резюме") {
		t.Errorf("EN markdown should not contain '## Резюме'")
	}
}

func TestReportWriteGeneratesBothRUandEN(t *testing.T) {
	c := sampleCaseForLocalization()
	dir := t.TempDir()

	if err := Write(dir, c); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	ruBytes, err := os.ReadFile(filepath.Join(dir, "report.md"))
	if err != nil {
		t.Fatalf("reading report.md: %v", err)
	}
	ruContent := string(ruBytes)
	if !strings.Contains(ruContent, "# Анализ уязвимости: GO-2026-6443") || !strings.Contains(ruContent, "## Резюме") {
		t.Fatalf("report.md does not contain expected RU content:\n%s", ruContent)
	}

	enBytes, err := os.ReadFile(filepath.Join(dir, "report.en.md"))
	if err != nil {
		t.Fatalf("reading report.en.md: %v", err)
	}
	enContent := string(enBytes)
	if !strings.Contains(enContent, "# Vulnerability analysis: GO-2026-6443") || !strings.Contains(enContent, "## Executive Summary") {
		t.Fatalf("report.en.md does not contain expected EN content:\n%s", enContent)
	}

	for _, name := range []string{"report.json", "openvex.json", "cyclonedx.json"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("expected file %s to exist: %v", name, err)
		}
	}
}

func TestReportNoDetailsTags(t *testing.T) {
	c := sampleCaseForLocalization()
	for _, lang := range []string{"ru", "en"} {
		md := Markdown(c, lang)
		if strings.Contains(md, "<details>") {
			t.Errorf("[%s] output should not contain <details>", lang)
		}
		if strings.Contains(md, "</details>") {
			t.Errorf("[%s] output should not contain </details>", lang)
		}
		if strings.Contains(md, "<summary>") || strings.Contains(md, "</summary>") {
			t.Errorf("[%s] output should not contain <summary> tags", lang)
		}
	}

	mdRU := Markdown(c, "ru")
	if !strings.Contains(mdRU, "## Технические детали и аудит (Data Flows, Tool Executions, Limitations)") {
		t.Errorf("RU output missing expected audit header")
	}

	mdEN := Markdown(c, "en")
	if !strings.Contains(mdEN, "## Technical Details & Audit (Data Flows, Tool Executions, Limitations)") {
		t.Errorf("EN output missing expected audit header")
	}
}

func TestReportClarityAndProvenance(t *testing.T) {
	c := &domain.AnalysisCase{
		ID: "case-clarity-test",
		Vulnerability: domain.Vulnerability{
			ID:     "CVE-2026-6443",
			Module: "example.com/mod",
			AffectedPackages: []domain.AffectedPackage{
				{Path: "example.com/mod/vulnpkg"},
			},
		},
		Product: domain.ProductSnapshot{
			Repository: "example.com/product",
			Commit:     "1234567890ab",
			GoVersion:  "1.24.0",
			GOOS:       "linux",
			GOARCH:     "amd64",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictNoExploitPathFound,
			Reason:  "mandatory exploit condition is proven false",
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
			VersionAffected: domain.ClaimTrue,
			PackagePresent:  domain.ClaimFalse,
			BuildRelevant:   domain.ClaimTrue,
		},
		Claims: []domain.Claim{
			{ConditionID: "C-LOCUS", Result: domain.ClaimFalse},
			{ConditionID: "C-REACH", Result: domain.ClaimTrue},
			{ConditionID: "C-PEER-INPUT", Result: domain.ClaimUnknown},
		},
		RootCause: &domain.RootCauseModel{
			Status: domain.RootCauseResolved,
			RootCauses: []domain.RootCause{
				{
					Package:   "example.com/mod/vulnpkg",
					Symbol:    "FaultyFunc",
					Role:      domain.RootCauseSink,
					Mechanism: "advisory-listed affected symbol",
				},
			},
		},
		Exploit: &domain.ExploitModel{
			Class:  "DENIAL_OF_SERVICE",
			Impact: "Server crash",
			MandatoryConditions: []domain.Condition{
				{ID: "C-LOCUS", Kind: "code", Description: "vulnerable function called"},
			},
			NonLocusBasis: []domain.LocusDecision{
				{
					Symbol:    domain.SymbolRef{Package: "example.com/mod/vulnpkg", Symbol: "SafeDispatcher"},
					Authority: "accepted-machine-proposal",
					Basis:     "helper dispatcher (accepted-machine-proposal)",
				},
			},
			LocusSubjects: []domain.SymbolRef{
				{Package: "example.com/mod/vulnpkg", Symbol: "FaultyFunc"},
			},
		},
		EvidenceGraph: domain.EvidenceGraph{
			ToolExecutions: []domain.ToolExecution{
				{Tool: "govulncheck", Args: []string{"./..."}, ExitCode: 0, DurationMs: 120, StdoutSHA256: "abcdef123456"},
			},
			Evidence: []domain.Evidence{
				{Kind: domain.EvidencePackageList, Content: "example.com/mod/vulnpkg\n"},
			},
		},
	}

	md := Markdown(c, "ru")

	// 1. Humanize Affected Analysis booleans in Russian: TRUE -> Да, FALSE -> Нет, UNKNOWN -> Не определено
	if !strings.Contains(md, "| Наличие модуля в зависимостях | Да |") {
		t.Errorf("expected '| Наличие модуля в зависимостях | Да |', got:\n%s", md)
	}
	if !strings.Contains(md, "| Версия входит в диапазон уязвимых | Да |") {
		t.Errorf("expected '| Версия входит в диапазон уязвимых | Да |'")
	}
	if !strings.Contains(md, "| Уязвимый пакет входит в сборку | Нет |") {
		t.Errorf("expected '| Уязвимый пакет входит в сборку | Нет |'")
	}
	if !strings.Contains(md, "| Код компилируется для целевой платформы | Да |") {
		t.Errorf("expected '| Код компилируется для целевой платформы | Да |'")
	}
	if strings.Contains(md, "| Наличие модуля в зависимостях | TRUE |") || strings.Contains(md, "| Уязвимый пакет входит в сборку | FALSE |") {
		t.Errorf("Affected table should not contain raw TRUE/FALSE booleans")
	}

	// 2. Humanize Claims table in Russian:
	// TRUE -> Подтверждено (TRUE), FALSE -> Опровергнуто (FALSE), UNKNOWN -> Не определено (UNKNOWN)
	if !strings.Contains(md, "| `C-LOCUS` | Опровергнуто (FALSE) |") {
		t.Errorf("expected C-LOCUS to show 'Опровергнуто (FALSE)'")
	}
	if !strings.Contains(md, "| `C-REACH` | Подтверждено (TRUE) |") {
		t.Errorf("expected C-REACH to show 'Подтверждено (TRUE)'")
	}
	if !strings.Contains(md, "| `C-PEER-INPUT` | Не определено (UNKNOWN) |") {
		t.Errorf("expected C-PEER-INPUT to show 'Не определено (UNKNOWN)'")
	}

	// 3. Root Causes: advisory-listed affected symbol -> заявлена как уязвимая в базе (advisory)
	if !strings.Contains(md, "заявлена как уязвимая в базе (advisory)") {
		t.Errorf("expected 'заявлена как уязвимая в базе (advisory)' in root causes")
	}
	if strings.Contains(md, "advisory-listed affected symbol") {
		t.Errorf("should not contain 'advisory-listed affected symbol'")
	}

	// 4. Locus Exclusions:
	// Header: #### Функции без дефекта (исключены из анализа уязвимости)
	// Text: Функции из базы уязвимости (advisory), которые признаны безопасными (являются вспомогательными диспетчерами или проверками входных данных) и не содержат дефектной операции:
	// Notes: replace accepted-machine-proposal with принятая рекомендация анализатора
	if !strings.Contains(md, "#### Функции без дефекта (исключены из анализа уязвимости)") {
		t.Errorf("missing Locus Exclusions header: '#### Функции без дефекта (исключены из анализа уязвимости)'")
	}
	if strings.Contains(md, "#### Экспертные решения non_locus") {
		t.Errorf("should not contain old header '#### Экспертные решения non_locus'")
	}
	if !strings.Contains(md, "Функции из базы уязвимости (advisory), которые признаны безопасными (являются вспомогательными диспетчерами или проверками входных данных) и не содержат дефектной операции:") {
		t.Errorf("missing humanized Locus Exclusions description")
	}
	if !strings.Contains(md, "принятая рекомендация анализатора") {
		t.Errorf("expected 'принятая рекомендация анализатора' in place of 'accepted-machine-proposal'")
	}
	if strings.Contains(md, "accepted-machine-proposal") {
		t.Errorf("should not contain 'accepted-machine-proposal'")
	}

	// 5. Govulncheck status in Affected Analysis table
	if !strings.Contains(md, "| Статический анализ вызовов (govulncheck) | Трасса вызовов от кода продукта не обнаружена (чисто) |") {
		t.Errorf("missing govulncheck status row in Affected Analysis table")
	}

	// 6. Provenance Breakdown under ## Доказательная база: ### Источники и методы проверки (Методология)
	expectedProvenancePhrases := []string{
		"### Источники и методы проверки (Методология)",
		"⚙️ **Детерминированные проверки компилятора Go:**",
		"Зависимости (`go.mod` / `go list -m`): версия модуля зафиксирована в сборке.",
		"Граф сборки (`go list -deps`): физическое отсутствие пакетов локуса дефекта в скомпилированном бинарнике.",
		"Статический анализ вызовов (`govulncheck`): проверка отсутствия пути вызова от приложения к уязвимым функциям.",
		"Анализ точек входа (AST): вызов стандартных безопасных конструкторов.",
		"🤖 **Семантический анализ LLM (AI-исследование):**",
		"Архитектурный анализ уязвимости: исследование патча, разделение функций на сайт паники и вспомогательные функции.",
		"Семантическое рецензирование: подтверждение логики работы компонентов.",
	}
	for _, phrase := range expectedProvenancePhrases {
		if !strings.Contains(md, phrase) {
			t.Errorf("provenance breakdown missing expected phrase: %q", phrase)
		}
	}

	if strings.Contains(md, "non_locus") {
		t.Errorf("Russian report should not contain raw 'non_locus' jargon, got:\n%s", md)
	}
}
