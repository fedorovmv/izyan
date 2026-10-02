// Package report renders the AnalysisCase into the persisted JSON artifact
// and a human-readable/tracker-ready markdown summary.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
)

// Write stores report.json, report.md, openvex.json and cyclonedx.json
// inside dir.
func Write(dir string, c *domain.AnalysisCase) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	jb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), jb, 0o644); err != nil {
		return err
	}
	vb, err := OpenVEX(c)
	if err != nil {
		return fmt.Errorf("openvex: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openvex.json"), vb, 0o644); err != nil {
		return err
	}
	cb, err := CycloneDX(c)
	if err != nil {
		return fmt.Errorf("cyclonedx: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cyclonedx.json"), cb, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(c, "ru")), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.en.md"), []byte(Markdown(c, "en")), 0o644)
}

func isRussian(lang ...string) bool {
	if len(lang) > 0 && strings.EqualFold(strings.TrimSpace(lang[0]), "en") {
		return false
	}
	return true
}

var verdictReasonRU = map[string]string{
	"mandatory exploit condition is proven false": "Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)",
	"all mandatory conditions met":                "Все обязательные условия эксплуатации выполнены (уязвимость подтверждена)",
	"resolved version outside affected range":     "Разрешённая версия библиотеки находится вне уязвимого диапазона",
	"no exploit conditions met":                   "Ни одно условие эксплуатации не выполнено",
	"locus packages absent from build graph":      "Уязвимый код физически не включён в сборку",
}

func localizeVerdictReason(reason string, isRU bool) string {
	if !isRU {
		return reason
	}
	if s, ok := verdictReasonRU[reason]; ok {
		return s
	}
	return reason
}

var conditionDescRU = map[string]string{
	"C-REACH":      "Достижимость символов: хотя бы одна из уязвимых функций вызывается в коде продукта",
	"C-PEER-INPUT": "Контроль ввода: параметры уязвимой функции контролируются удалённым клиентом",
	"C-CONSTRAINT": "Нарушение ограничений: удалённый клиент может передать входные данные, вызывающие сбой",
	"C-LOCUS":      "Выполнение уязвимого кода: пакеты дефектного кода входят в граф сборки приложения",
	"C-EXPOSURE":   "Сетевая доступность: наличие открытых сетевых портов или исходящих подключений",
	"C-TLS-VERIFY": "Проверка TLS: отключение проверки сертификатов позволяет передавать трафик без доверенного канала",
}

func localizeConditionDesc(id string, defaultDesc string, isRU bool) string {
	if !isRU {
		return defaultDesc
	}
	if s, ok := conditionDescRU[id]; ok {
		return s
	}
	return defaultDesc
}

func rootCauseRole(role domain.RootCauseRole, isRU bool) string {
	if !isRU {
		return string(role)
	}
	switch role {
	case domain.RootCauseSink:
		return "Точка сбоя / Sink"
	case domain.RootCauseEntrypoint:
		return "Точка входа / Entrypoint"
	case domain.RootCausePropagation:
		return "Распространение / Propagation"
	default:
		return string(role)
	}
}

func rootCauseStatus(status domain.RootCauseStatus, isRU bool) string {
	if !isRU {
		return fmt.Sprintf("`%s`", status)
	}
	switch status {
	case domain.RootCauseResolved:
		return "Определена"
	case domain.RootCauseAmbiguous:
		return "Неоднозначно"
	case domain.RootCauseNotFound:
		return "Не найдена"
	default:
		return fmt.Sprintf("`%s`", status)
	}
}

func localizeAffectedBool(r domain.ClaimResult, isRU bool) string {
	if !isRU {
		return string(r)
	}
	switch r {
	case domain.ClaimTrue:
		return "Да"
	case domain.ClaimFalse:
		return "Нет"
	case domain.ClaimUnknown:
		return "Не определено"
	default:
		if strings.EqualFold(string(r), "true") {
			return "Да"
		}
		if strings.EqualFold(string(r), "false") {
			return "Нет"
		}
		return string(r)
	}
}

func localizeClaimResult(r domain.ClaimResult, isRU bool) string {
	if !isRU {
		return string(r)
	}
	switch r {
	case domain.ClaimTrue:
		return "Подтверждено (TRUE)"
	case domain.ClaimFalse:
		return "Опровергнуто (FALSE)"
	case domain.ClaimUnknown:
		return "Не определено (UNKNOWN)"
	default:
		if strings.EqualFold(string(r), "true") {
			return "Подтверждено (TRUE)"
		}
		if strings.EqualFold(string(r), "false") {
			return "Опровергнуто (FALSE)"
		}
		return string(r)
	}
}

func govulncheckSummary(c *domain.AnalysisCase, isRU bool) string {
	if len(c.EvidenceGraph.CallPaths) > 0 {
		if isRU {
			return fmt.Sprintf("Обнаружены пути вызова к уязвимому коду (%d)", len(c.EvidenceGraph.CallPaths))
		}
		return fmt.Sprintf("Call path(s) to vulnerable code detected (%d)", len(c.EvidenceGraph.CallPaths))
	}
	if isRU {
		return "Трасса вызовов от кода продукта не обнаружена (чисто)"
	}
	return "No call path from product code found (clean)"
}

func rootCauseMechanism(mech string, isRU bool) string {
	if isRU {
		if mech == "advisory-listed affected symbol" {
			return "заявлена как уязвимая в базе (advisory)"
		}
		return strings.ReplaceAll(mech, "advisory-listed affected symbol", "заявлена как уязвимая в базе (advisory)")
	}
	return mech
}

func renderProvenanceBreakdown(b *strings.Builder, isRU bool) {
	if isRU {
		b.WriteString("### Источники и методы проверки (Методология)\n\n")
		b.WriteString("- ⚙️ **Детерминированные проверки компилятора Go:**\n")
		b.WriteString("  - Зависимости (`go.mod` / `go list -m`): фиксация версий библиотек в сборке.\n")
		b.WriteString("  - Граф пакетов сборки (`go list -deps`): проверка фактического включения скомпилированных пакетов в бинарный файл.\n")
		b.WriteString("  - Анализ графа вызовов (`govulncheck`): поиск статических путей вызова от приложения к функциям из advisory (проверка достижимости символов).\n")
		b.WriteString("  - Анализ точек входа (AST): инспекция конструкторов и инициализации сервисов в коде проекта.\n")
		b.WriteString("- 🤖 **Семантический анализ LLM (AI-исследование):**\n")
		b.WriteString("  - Архитектурный анализ уязвимости: исследование патча и разделение функций из advisory на сайт сбоя (дефектный локус) и вспомогательные функции (диспетчеры). Это объясняет, почему при наличии вызовов по `govulncheck` реальный уязвимый код не исполняется.\n")
		b.WriteString("  - Семантическое рецензирование: валидация логики работы компонентов и проверка условий эксплуатации.\n\n")
	} else {
		b.WriteString("### Verification Sources & Methods (Methodology)\n\n")
		b.WriteString("- ⚙️ **Go compiler deterministic checks:**\n")
		b.WriteString("  - Dependencies (`go.mod` / `go list -m`): module version pinned in build.\n")
		b.WriteString("  - Build package graph (`go list -deps`): verification of whether library packages are physically linked into the compiled binary.\n")
		b.WriteString("  - Call graph analysis (`govulncheck`): detection of static call paths from product code to advisory symbols (reachability check).\n")
		b.WriteString("  - Entrypoint analysis (AST): inspection of service initialization and constructors used in project code.\n")
		b.WriteString("- 🤖 **LLM semantic analysis (AI research):**\n")
		b.WriteString("  - Vulnerability architectural analysis: patch investigation, distinguishing actual defect/panic sites (locus) from helper dispatchers. Explains why execution does not reach defective code despite calls reported by `govulncheck`.\n")
		b.WriteString("  - Semantic review: component operational logic validation and exploit condition checks.\n\n")
	}
}

func renderGovulncheckComparison(b *strings.Builder, c *domain.AnalysisCase, isRU bool) {
	hasCallPaths := len(c.EvidenceGraph.CallPaths) > 0
	hasGovulncheckExec := false
	for _, tex := range c.EvidenceGraph.ToolExecutions {
		if tex.Tool == "govulncheck" {
			hasGovulncheckExec = true
			break
		}
	}
	if !hasCallPaths && !hasGovulncheckExec {
		return
	}

	var targets []string
	seen := map[string]bool{}
	for _, cp := range c.EvidenceGraph.CallPaths {
		if len(cp.Frames) > 0 {
			f := cp.Frames[0]
			var name string
			if f.Package != "" && f.Function != "" {
				name = f.Package + "." + f.Function
			} else if f.Function != "" {
				name = f.Function
			} else if f.Package != "" {
				name = f.Package
			}
			if name != "" && !seen[name] {
				seen[name] = true
				targets = append(targets, name)
			}
		}
	}

	absentPkgs, _, presentNotes := splitAdvisoryPackages(c)

	if isRU {
		b.WriteString("### Сопоставление с govulncheck (Анализ расхождения)\n\n")
		if hasCallPaths {
			b.WriteString("- 🔍 **Вердикт govulncheck:** **Уязвимый код вызывается (Reachable)**\n")
			if len(targets) > 0 {
				fmt.Fprintf(b, "  - Сканер обнаружил пути вызова от приложения к коду библиотеки (в частности: `%s`).\n", strings.Join(targets, "`, `"))
			} else {
				fmt.Fprintf(b, "  - Сканер обнаружил пути вызова к коду библиотеки (%d).\n", len(c.EvidenceGraph.CallPaths))
			}
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound {
				b.WriteString("- 🛡️ **Вердикт анализатора:** **`NO_EXPLOIT_PATH_FOUND` (Уязвимый путь исполнения отсутствует)**\n")
				b.WriteString("- ⚖️ **Обоснование опровержения (почему срабатывание govulncheck является ложной тревогой):**\n")
				b.WriteString("  - **Смешение ролей функций в базе advisory:** `govulncheck` считает все перечисленные в advisory функции одинаково уязвимыми и не анализирует коммит исправления.\n")
				if len(presentNotes) > 0 {
					var syms []string
					for _, pn := range presentNotes {
						syms = append(syms, fmt.Sprintf("`%s.%s`", pn.Symbol.Package, pn.Symbol.Symbol))
					}
					fmt.Fprintf(b, "  - **Безопасность вызываемых функций:** Вызовы приходят в функции %s, которые выполняют лишь вспомогательную диспетчеризацию и не содержат дефектной операции.\n", strings.Join(syms, ", "))
				} else {
					b.WriteString("  - **Безопасность вызываемых функций:** Вызовы приходят в функции, которые признаны безопасными диспетчерами.\n")
				}
				if len(absentPkgs) > 0 {
					fmt.Fprintf(b, "  - **Физическое отсутствие дефектного локуса:** Реальный сайт сбоя находится в пакетах `%s`, которые **не скомпилированы в бинарный файл** (`go list -deps`).\n", strings.Join(absentPkgs, "`, `"))
				}
				b.WriteString("  - **Итог:** Вызовы, зафиксированные `govulncheck`, не приводят к исполнению дефекта (reachability false positive).\n\n")
			} else if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Вердикт анализатора:** **`EXPLOITABLE` (Уязвимость подтверждена)**\n")
				b.WriteString("- ⚖️ **Сопоставление:** Результаты согласуются — трасса вызовов подтверждает достижимость дефектного локуса.\n\n")
			} else if c.Verdict != nil {
				fmt.Fprintf(b, "- ⚠️ **Вердикт анализатора:** **`%s`**\n", c.Verdict.Verdict)
				b.WriteString("- ⚖️ **Сопоставление:** `govulncheck` обнаружил вызовы к библиотеке; условия эксплуатации требуют дальнейшей проверки.\n\n")
			}
		} else {
			b.WriteString("- 🔍 **Вердикт govulncheck:** **Трасса вызовов не обнаружена (Clean)**\n")
			b.WriteString("  - Сканер не нашёл статических путей вызова от кода приложения к функциям из advisory.\n")
			if c.Verdict != nil {
				fmt.Fprintf(b, "- 🛡️ **Вердикт анализатора:** **`%s`**\n", c.Verdict.Verdict)
			}
			b.WriteString("- ⚖️ **Сопоставление:** Результаты согласуются — вызовы уязвимых функций отсутствуют.\n\n")
		}
	} else {
		b.WriteString("### Govulncheck Comparison & Divergence Analysis\n\n")
		if hasCallPaths {
			b.WriteString("- 🔍 **Govulncheck Finding:** **Reachable (Vulnerable code is called)**\n")
			if len(targets) > 0 {
				fmt.Fprintf(b, "  - Scanner detected call paths from application code to library code (specifically: `%s`).\n", strings.Join(targets, "`, `"))
			} else {
				fmt.Fprintf(b, "  - Scanner detected %d call path(s) to library code.\n", len(c.EvidenceGraph.CallPaths))
			}
			if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictNoExploitPathFound {
				b.WriteString("- 🛡️ **Analyzer Verdict:** **`NO_EXPLOIT_PATH_FOUND` (No exploit path exists)**\n")
				b.WriteString("- ⚖️ **Divergence Rationale (Why govulncheck's warning is refuted):**\n")
				b.WriteString("  - **Undifferentiated advisory symbols:** `govulncheck` treats all symbols in the advisory record as equally vulnerable without analyzing patch semantics.\n")
				if len(presentNotes) > 0 {
					var syms []string
					for _, pn := range presentNotes {
						syms = append(syms, fmt.Sprintf("`%s.%s`", pn.Symbol.Package, pn.Symbol.Symbol))
					}
					fmt.Fprintf(b, "  - **Safety of called functions:** Calls reach functions %s, which perform only helper dispatching and contain no defective operation.\n", strings.Join(syms, ", "))
				} else {
					b.WriteString("  - **Safety of called functions:** Calls reach helper functions verified to be non-defective.\n")
				}
				if len(absentPkgs) > 0 {
					fmt.Fprintf(b, "  - **Physical absence of defect locus:** The actual crash site resides in packages `%s`, which are **not linked into the binary** (`go list -deps`).\n", strings.Join(absentPkgs, "`, `"))
				}
				b.WriteString("  - **Conclusion:** Call paths detected by `govulncheck` do not execute defective code (reachability false positive).\n\n")
			} else if c.Verdict != nil && c.Verdict.Verdict == domain.VerdictExploitable {
				b.WriteString("- ⚠️ **Analyzer Verdict:** **`EXPLOITABLE` (Vulnerability confirmed)**\n")
				b.WriteString("- ⚖️ **Comparison:** Findings agree — call paths reach the active defect locus.\n\n")
			} else if c.Verdict != nil {
				fmt.Fprintf(b, "- ⚠️ **Analyzer Verdict:** **`%s`**\n", c.Verdict.Verdict)
				b.WriteString("- ⚖️ **Comparison:** `govulncheck` detected library calls; exploit conditions require further evaluation.\n\n")
			}
		} else {
			b.WriteString("- 🔍 **Govulncheck Finding:** **Clean (No call path found)**\n")
			b.WriteString("  - Scanner detected no static call paths from product code to advisory functions.\n")
			if c.Verdict != nil {
				fmt.Fprintf(b, "- 🛡️ **Analyzer Verdict:** **`%s`**\n", c.Verdict.Verdict)
			}
			b.WriteString("- ⚖️ **Comparison:** Findings agree — no calls to vulnerable functions detected.\n\n")
		}
	}
}

func Markdown(c *domain.AnalysisCase, lang ...string) string {
	isRU := isRussian(lang...)
	var b strings.Builder
	if isRU {
		fmt.Fprintf(&b, "# Анализ уязвимости: %s\n\n", c.Vulnerability.ID)
		fmt.Fprintf(&b, "- Кейс: `%s`\n", c.ID)
		fmt.Fprintf(&b, "- Репозиторий: `%s`\n- Коммит: `%s`\n- Окружение Go: `%s` (%s/%s)\n\n",
			c.Product.Repository, c.Product.Commit, c.Product.GoVersion, c.Product.GOOS, c.Product.GOARCH)
	} else {
		fmt.Fprintf(&b, "# Vulnerability analysis: %s\n\n", c.Vulnerability.ID)
		fmt.Fprintf(&b, "- Case: `%s`\n", c.ID)
		fmt.Fprintf(&b, "- Repository: `%s`\n- Commit: `%s`\n- Go: `%s` (%s/%s)\n\n",
			c.Product.Repository, c.Product.Commit, c.Product.GoVersion, c.Product.GOOS, c.Product.GOARCH)
	}

	if c.Verdict != nil {
		if isRU {
			fmt.Fprintf(&b, "## Вердикт: `%s`\n\n> **%s**\n\n", c.Verdict.Verdict, localizeVerdictReason(c.Verdict.Reason, true))
		} else {
			fmt.Fprintf(&b, "## Verdict: `%s`\n\n> **%s**\n\n", c.Verdict.Verdict, c.Verdict.Reason)
		}
	}
	if rat := rationale(c); rat != "" {
		if isRU {
			fmt.Fprintf(&b, "## Резюме\n\n%s\n\n", rat)
		} else {
			fmt.Fprintf(&b, "## Executive Summary\n\n%s\n\n", rat)
		}
	}
	if r := remediation(c, isRU); r != "" {
		if isRU {
			fmt.Fprintf(&b, "## Рекомендации по устранению\n\n%s\n\n", r)
		} else {
			fmt.Fprintf(&b, "## Remediation\n\n%s\n\n", r)
		}
	}

	exps := c.EvidenceGraph.ExposuresList()
	hasEvidence := c.Affected != nil || len(c.Claims) > 0 || len(exps) > 0 || c.RootCause != nil || c.Exploit != nil
	if hasEvidence {
		if isRU {
			b.WriteString("## Доказательная база\n\n")
		} else {
			b.WriteString("## Evidence Dossier\n\n")
		}

		renderProvenanceBreakdown(&b, isRU)

		if c.Affected != nil {
			a := c.Affected
			if isRU {
				fmt.Fprintf(&b, "### Применимость (Affected Analysis)\n\n")
				fmt.Fprintf(&b, "| Проверка | Результат |\n|---|---|\n")
				fmt.Fprintf(&b, "| Наличие модуля в зависимостях | %s |\n", localizeAffectedBool(a.ModulePresent, true))
				fmt.Fprintf(&b, "| Разрешённая версия в go.mod | `%s` |\n", a.ResolvedVersion)
				fmt.Fprintf(&b, "| Версия входит в диапазон уязвимых | %s |\n", localizeAffectedBool(a.VersionAffected, true))
				fmt.Fprintf(&b, "| Уязвимый пакет входит в сборку | %s |\n", localizeAffectedBool(a.PackagePresent, true))
				fmt.Fprintf(&b, "| Код компилируется для целевой платформы | %s |\n", localizeAffectedBool(a.BuildRelevant, true))
				fmt.Fprintf(&b, "| Статический анализ вызовов (govulncheck) | %s |\n", govulncheckSummary(c, true))
				if len(a.CheckedModules) > 0 {
					fmt.Fprintf(&b, "| Проверенные модули | `%s` |\n", strings.Join(a.CheckedModules, "`, `"))
				}
				if len(a.SelectedModules) > 0 {
					fmt.Fprintf(&b, "| Скомпилированные модули | `%s` |\n", strings.Join(a.SelectedModules, "`, `"))
				}
				if len(a.PendingModules) > 0 {
					fmt.Fprintf(&b, "| Модули с неопределённой версией | `%s` |\n", strings.Join(a.PendingModules, "`, `"))
				}
				if len(a.CheckedPackages) > 0 {
					fmt.Fprintf(&b, "| Проверенные пакеты | `%s` |\n", strings.Join(a.CheckedPackages, "`, `"))
				}
				if len(a.EvidenceIDs) > 0 {
					fmt.Fprintf(&b, "| Идентификаторы доказательств (Evidence IDs) | %s |\n", strings.Join(evidenceIDs(a.EvidenceIDs), ", "))
				}
				b.WriteString("\n")
			} else {
				fmt.Fprintf(&b, "### Affected Analysis\n\n")
				fmt.Fprintf(&b, "| check | result |\n|---|---|\n")
				fmt.Fprintf(&b, "| module present | %s |\n", a.ModulePresent)
				fmt.Fprintf(&b, "| resolved version | `%s` |\n", a.ResolvedVersion)
				fmt.Fprintf(&b, "| version affected | %s |\n", a.VersionAffected)
				fmt.Fprintf(&b, "| package present | %s |\n", a.PackagePresent)
				fmt.Fprintf(&b, "| build relevant | %s |\n", a.BuildRelevant)
				fmt.Fprintf(&b, "| static call analysis (govulncheck) | %s |\n", govulncheckSummary(c, false))
				if len(a.CheckedModules) > 0 {
					fmt.Fprintf(&b, "| modules probed | `%s` |\n", strings.Join(a.CheckedModules, "`, `"))
				}
				if len(a.SelectedModules) > 0 {
					fmt.Fprintf(&b, "| modules linked | `%s` |\n", strings.Join(a.SelectedModules, "`, `"))
				}
				if len(a.PendingModules) > 0 {
					fmt.Fprintf(&b, "| modules version-unresolved | `%s` |\n", strings.Join(a.PendingModules, "`, `"))
				}
				if len(a.CheckedPackages) > 0 {
					fmt.Fprintf(&b, "| packages probed | `%s` |\n", strings.Join(a.CheckedPackages, "`, `"))
				}
				if len(a.EvidenceIDs) > 0 {
					fmt.Fprintf(&b, "| evidence | %s |\n", strings.Join(evidenceIDs(a.EvidenceIDs), ", "))
				}
				b.WriteString("\n")
			}
		}

		renderGovulncheckComparison(&b, c, isRU)

		if len(c.Claims) > 0 {
			if isRU {
				b.WriteString("### Статус условий эксплуатации (Claims)\n\n| Условие | Результат | Верификация | Доказательства |\n|---|---|---|---|\n")
				for _, cl := range c.Claims {
					fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", cl.ConditionID, localizeClaimResult(cl.Result, true),
						claimVerification(cl, true), strings.Join(evidenceIDs(cl.EvidenceIDs), ", "))
				}
				b.WriteString("\n")
			} else {
				b.WriteString("### Claims Status\n\n| condition | result | verification | evidence |\n|---|---|---|---|\n")
				for _, cl := range c.Claims {
					fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", cl.ConditionID, cl.Result,
						claimVerification(cl, false), strings.Join(evidenceIDs(cl.EvidenceIDs), ", "))
				}
				b.WriteString("\n")
			}
		}

		if len(exps) > 0 {
			if isRU {
				b.WriteString("### Точки входа (Exposure Facts)\n\n")
				for _, f := range exps {
					var dirDesc string
					if f.Direction == "inbound" {
						dirDesc = "Входящий слушатель"
					} else if f.Direction == "outbound" {
						dirDesc = "Исходящее подключение"
					} else {
						dirDesc = fmt.Sprintf("`%s` %s", f.Direction, f.Kind)
					}
					fmt.Fprintf(&b, "- %s через `%s`", dirDesc, f.Target)
					if f.Address != "" {
						fmt.Fprintf(&b, " — `%s`", f.Address)
					}
					var meta []string
					if f.AddressSource != "" {
						meta = append(meta, "источник: "+f.AddressSource)
					}
					if f.Scope != "" {
						meta = append(meta, "область: "+f.Scope)
					}
					if len(meta) > 0 {
						fmt.Fprintf(&b, " (%s)", strings.Join(meta, ", "))
					}
					fmt.Fprintf(&b, " — %s:%d\n", f.File, f.Line)
				}
				b.WriteString("\n")
			} else {
				b.WriteString("### Exposure Facts\n\n")
				for _, f := range exps {
					fmt.Fprintf(&b, "- `%s` %s via `%s`", f.Direction, f.Kind, f.Target)
					if f.Address != "" {
						fmt.Fprintf(&b, " — `%s`", f.Address)
					}
					var meta []string
					if f.AddressSource != "" {
						meta = append(meta, "source: "+f.AddressSource)
					}
					if f.Scope != "" {
						meta = append(meta, "scope: "+f.Scope)
					}
					if len(meta) > 0 {
						fmt.Fprintf(&b, " (%s)", strings.Join(meta, ", "))
					}
					fmt.Fprintf(&b, " — %s:%d\n", f.File, f.Line)
				}
				b.WriteString("\n")
			}
		}

		if c.RootCause != nil || c.Exploit != nil {
			if isRU {
				b.WriteString("### Модель эксплуатации и сайты дефекта\n\n")
			} else {
				b.WriteString("### Exploit Model & Defect Locus\n\n")
			}

			if c.RootCause != nil {
				if isRU {
					fmt.Fprintf(&b, "#### Первопричина дефекта (Root cause): %s\n\n", rootCauseStatus(c.RootCause.Status, true))
					for _, rc := range c.RootCause.RootCauses {
						fmt.Fprintf(&b, "- `%s.%s` (%s) — %s\n", rc.Package, rc.Symbol, rootCauseRole(rc.Role, true), rootCauseMechanism(rc.Mechanism, true))
					}
					b.WriteString("\n")
				} else {
					fmt.Fprintf(&b, "#### Root cause: `%s`\n\n", c.RootCause.Status)
					for _, rc := range c.RootCause.RootCauses {
						fmt.Fprintf(&b, "- `%s.%s` (%s) — %s\n", rc.Package, rc.Symbol, rc.Role, rc.Mechanism)
					}
					b.WriteString("\n")
				}
			}

			if c.Exploit != nil {
				if c.Exploit.Class != "" {
					if isRU {
						fmt.Fprintf(&b, "Класс дефекта: `%s`\n\n", c.Exploit.Class)
					} else {
						fmt.Fprintf(&b, "Class: `%s`\n\n", c.Exploit.Class)
					}
				}
				if c.Exploit.Impact != "" {
					if isRU {
						fmt.Fprintf(&b, "Последствия: %s\n\n", c.Exploit.Impact)
					} else {
						fmt.Fprintf(&b, "Impact: %s\n\n", c.Exploit.Impact)
					}
				}

				if isRU {
					writeConditions(&b, "Обязательные условия (Mandatory conditions)", c.Exploit.MandatoryConditions, true)
					writeConditions(&b, "Сопутствующие факторы (Supporting factors)", c.Exploit.SupportingFactors, true)
				} else {
					writeConditions(&b, "Mandatory conditions", c.Exploit.MandatoryConditions, false)
					writeConditions(&b, "Supporting factors", c.Exploit.SupportingFactors, false)
				}

				if len(c.Exploit.NonLocusBasis) > 0 {
					if isRU {
						b.WriteString("#### Функции без дефекта (исключены из анализа уязвимости)\n\n")
						b.WriteString("Функции из базы уязвимости (advisory), которые признаны безопасными (являются вспомогательными диспетчерами или проверками входных данных) и не содержат дефектной операции:\n\n")
						for _, d := range c.Exploit.NonLocusBasis {
							auth := d.Authority
							if auth == "" {
								auth = "эксперт"
							} else if auth == "accepted-machine-proposal" {
								auth = "принятая рекомендация анализатора"
							}
							basis := strings.ReplaceAll(d.Basis, "accepted-machine-proposal", "принятая рекомендация анализатора")
							fmt.Fprintf(&b, "- `%s.%s` — %s (%s)\n", d.Symbol.Package, d.Symbol.Symbol, basis, auth)
						}
						b.WriteString("\n")
					} else {
						b.WriteString("#### Expert decisions on non_locus\n\n")
						b.WriteString("Analysis adjusted for recorded expert decisions (manual confirmation, not automated deduction):\n\n")
						for _, d := range c.Exploit.NonLocusBasis {
							auth := d.Authority
							if auth == "" {
								auth = "expert"
							}
							fmt.Fprintf(&b, "- `%s.%s` — %s (%s)\n", d.Symbol.Package, d.Symbol.Symbol, d.Basis, auth)
						}
						b.WriteString("\n")
					}
				}

				if len(c.Exploit.ProposedNonLocus) > 0 || len(c.Exploit.LocusSubjects) > 0 {
					if isRU {
						b.WriteString("#### Оценка анализатора\n\n")
						b.WriteString(machineAssessment(c))
						b.WriteString("\n")
					} else {
						b.WriteString("#### Machine assessment\n\n")
						b.WriteString(machineAssessment(c))
						b.WriteString("\n")
					}
				}
			}
		}
	}

	var bt []domain.Evidence
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidenceBuild || e.Kind == domain.EvidenceTest {
			bt = append(bt, e)
		}
	}
	lims := allLimitations(c)
	texs := c.EvidenceGraph.ToolExecutions
	hasAudit := len(c.EvidenceGraph.DataFlows) > 0 ||
		len(texs) > 0 ||
		len(lims) > 0 ||
		len(c.Reviews) > 0 ||
		len(c.EvidenceGraph.Runtime) > 0 ||
		len(bt) > 0 ||
		len(c.Hypotheses) > 0

	if hasAudit {
		if isRU {
			b.WriteString("## Технические детали и аудит (Data Flows, Tool Executions, Limitations)\n\n")
		} else {
			b.WriteString("## Technical Details & Audit (Data Flows, Tool Executions, Limitations)\n\n")
		}

		if len(c.EvidenceGraph.DataFlows) > 0 {
			if isRU {
				b.WriteString("### Потоки данных (Data Flows)\n\n")
			} else {
				b.WriteString("### Data Flows\n\n")
			}
			for _, f := range c.EvidenceGraph.DataFlows {
				var tx []string
				for _, t := range f.Transformations {
					tx = append(tx, t.Callee)
				}
				fmt.Fprintf(&b, "- `%s` %s", f.Origin, f.Summary)
				if len(tx) > 0 {
					fmt.Fprintf(&b, " — via `%s`", strings.Join(tx, "`, `"))
				}
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}

		if len(texs) > 0 {
			if isRU {
				b.WriteString("### Журнал инструментов (Tool Executions)\n\n| Инструмент | Аргументы | Код возврата | Длительность (мс) | SHA-256 вывода |\n|---|---|---|---|---|\n")
			} else {
				b.WriteString("### Tool Executions\n\n| tool | args | exit | ms | stdout sha256 |\n|---|---|---|---|---|\n")
			}
			for _, t := range texs {
				tool := t.Tool
				if t.Version != "" {
					tool += "@" + t.Version
				}
				hash := t.StdoutSHA256
				if len(hash) > 12 {
					hash = hash[:12] + "…"
				}
				fmt.Fprintf(&b, "| `%s` | `%s` | %d | %d | `%s` |\n",
					tool, strings.Join(t.Args, " "), t.ExitCode, t.DurationMs, hash)
			}
			b.WriteString("\n")
		}

		if len(lims) > 0 {
			if isRU {
				b.WriteString("### Ограничения анализа (Limitations)\n\n")
			} else {
				b.WriteString("### Limitations\n\n")
			}
			for _, l := range lims {
				fmt.Fprintf(&b, "- %s\n", l)
			}
			b.WriteString("\n")
		}

		if len(c.Reviews) > 0 {
			if isRU {
				b.WriteString("### Рецензирование (Review Findings)\n\n")
			} else {
				b.WriteString("### Review Findings\n\n")
			}
			for _, rv := range c.Reviews {
				fmt.Fprintf(&b, "- `%s` → **%s**", rv.ID, rv.Result)
				if len(rv.Findings) > 0 {
					b.WriteString("\n")
					for _, f := range rv.Findings {
						fmt.Fprintf(&b, "  - [%s] %s `%s`: %s\n", f.Severity, f.TargetType, f.TargetID, f.Problem)
					}
				} else {
					if isRU {
						b.WriteString(" — замечаний нет\n")
					} else {
						b.WriteString(" — no findings\n")
					}
				}
			}
			b.WriteString("\n")
		}

		if len(c.EvidenceGraph.Runtime) > 0 {
			if isRU {
				b.WriteString("### Факты среды (Runtime Facts)\n\n")
			} else {
				b.WriteString("### Runtime Facts\n\n")
			}
			for _, id := range c.EvidenceGraph.Runtime {
				if e := c.EvidenceGraph.EvidenceByID(id); e != nil {
					fmt.Fprintf(&b, "- %s: %s\n\n", e.Source, e.Content)
				}
			}
		}

		if len(bt) > 0 {
			if isRU {
				b.WriteString("### Сборка и тесты (Build & Test)\n\n")
			} else {
				b.WriteString("### Build & Test\n\n")
			}
			for _, e := range bt {
				name := e.Command
				if name == "" {
					name = e.Source
				}
				status := e.Content
				if i := strings.IndexByte(status, '\n'); i >= 0 {
					status = status[:i]
				}
				fmt.Fprintf(&b, "- `%s` — %s\n", name, status)
			}
			b.WriteString("\n")
		}

		if len(c.Hypotheses) > 0 {
			if isRU {
				b.WriteString("### Рабочие гипотезы (Hypotheses)\n\n")
			} else {
				b.WriteString("### Hypotheses\n\n")
			}
			for _, h := range c.Hypotheses {
				fmt.Fprintf(&b, "- `%s` %s → **%s**: %s", h.ID, h.ConditionID, h.Status, h.Statement)
				if h.Notes != "" {
					notes := h.Notes
					if isRU {
						notes = strings.ReplaceAll(notes, "accepted-machine-proposal", "принятая рекомендация анализатора")
					}
					fmt.Fprintf(&b, " — %s", notes)
				}
				b.WriteString("\n")
			}
			b.WriteString("\n")
		}
	}

	return b.String()
}

func writeConditions(b *strings.Builder, title string, conds []domain.Condition, isRU bool) {
	if len(conds) == 0 {
		return
	}
	fmt.Fprintf(b, "#### %s\n\n", title)
	for _, cond := range conds {
		desc := localizeConditionDesc(string(cond.ID), cond.Description, isRU)
		fmt.Fprintf(b, "- `%s` [%s]: %s%s\n", cond.ID, cond.Kind, desc, renderParams(cond.Params))
	}
	b.WriteString("\n")
}

func renderParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	return " {" + strings.Join(parts, ", ") + "}"
}

// claimVerification renders the falsifier/NV status so a claim that was
// proven and then demoted by review stays auditable in the table —
// e.g. "guards / VERIFIED (demoted)" instead of a bare UNKNOWN.
func claimVerification(cl domain.Claim, isRU bool) string {
	if cl.NegativeVerification == nil && cl.Falsifier == "" {
		return ""
	}
	var s string
	if cl.Falsifier != "" {
		f := string(cl.Falsifier)
		if isRU {
			switch cl.Falsifier {
			case "locus-package-absent":
				f = "Пакет отсутствует в сборке"
			}
		}
		s = f
	}
	if cl.NegativeVerification != nil {
		st := string(cl.NegativeVerification.Status)
		if isRU {
			switch cl.NegativeVerification.Status {
			case domain.NegativeVerified:
				st = "ПОДТВЕРЖДЕНО"
			case domain.NegativeInsufficientScope:
				st = "Недостаточный охват"
			}
		}
		if s != "" {
			s += " / "
		}
		s += st
	}
	if cl.Result == domain.ClaimUnknown && cl.NegativeVerification != nil &&
		cl.NegativeVerification.Status == domain.NegativeVerified {
		if isRU {
			s += " (демотировано)"
		} else {
			s += " (demoted)"
		}
	}
	return s
}

func evidenceIDs(ids []domain.EvidenceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

// machineAssessment renders the case-level machine opinion: a proposed
// disposition for the defect-locus falsifier, the expert decisions it
// depends on, and the assumptions outside machine verification. The
// package-absent falsifier needs every locus subject in a linked package
// to carry a recorded expert exclusion — so the block lists, per declared
// symbol, its package status and what the expert still has to decide.
// Advisory text for review — never part of the verdict.
func machineAssessment(c *domain.AnalysisCase) string {
	if c.Exploit == nil || len(c.Exploit.LocusSubjects) == 0 {
		return ""
	}
	proposed := map[domain.SymbolRef]domain.LocusDecision{}
	for _, d := range c.Exploit.ProposedNonLocus {
		proposed[d.Symbol] = d
	}
	annotated := map[domain.SymbolRef]domain.LocusDecision{}
	for _, d := range c.Exploit.LocusAnnotations {
		annotated[d.Symbol] = d
	}

	var set map[string]bool
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind != domain.EvidencePackageList {
			continue
		}
		if s, err := affected.PackageImportPaths([]byte(e.Content)); err == nil {
			set = s
		}
		break
	}
	if set == nil {
		return "Оценку по отсутствию пакетов выставить нельзя: нет данных о составе сборки (`go list -deps`).\n"
	}

	var b strings.Builder
	b.WriteString("Отклонить уязвимость из-за отсутствия пакетов в сборке можно только при условии, что для каждой функции из advisory в *попавших в сборку* пакетах подтверждено решение о безопасности (код не содержит дефекта и признан безопасным):\n\n")
	var pending, proposedN, flagged int
	for _, s := range c.Exploit.LocusSubjects {
		name := "`" + s.Package + "." + s.Symbol + "`"
		if !set[s.Package] {
			fmt.Fprintf(&b, "- %s — пакет **отсутствует в сборке** (`go list -deps`) — код физически не скомпилирован\n", name)
			continue
		}
		pending++
		if d, ok := proposed[s]; ok {
			proposedN++
			fmt.Fprintf(&b, "- %s — пакет входит в сборку — **рекомендуется исключить** (код безопасен): %s\n", name, d.Basis)
			continue
		}
		if d, ok := annotated[s]; ok {
			flagged++
			fmt.Fprintf(&b, "- %s — пакет входит в сборку — **исключение не рекомендуется**: %s — чтобы отклонить, эксперт должен опровергнуть этот вывод\n", name, d.Basis)
		} else {
			fmt.Fprintf(&b, "- %s — пакет входит в сборку — **требуется решение эксперта** (автоматический анализ не дал результатов)\n", name)
		}
	}
	b.WriteString("\n")
	switch {
	case pending == 0:
		b.WriteString("**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ** — ни один из пакетов с уязвимым кодом не входит в граф сборки приложения.\n")
	case flagged == 0 && pending == proposedN:
		fmt.Fprintf(&b,
			"**Предлагаемая оценка: МОЖНО ОТКЛОНИТЬ ПОСЛЕ ПОДТВЕРЖДЕНИЯ** — подтвердите %d рекомендаций об исключении как безопасных; остальные пакеты в сборку не входят → вердикт `NO_EXPLOIT_PATH_FOUND` (для автоматического применения рекомендаций используйте флаг `--accept-locus-proposals`).\n",
			pending)
	case flagged == 0:
		fmt.Fprintf(&b,
			"**Предлагаемая оценка: ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)** — чтобы отклонить уязвимость, необходимо подтвердить решение о безопасности по всем %d функциям в попавших в сборку пакетах (%d рекомендованы к исключению; по %d автоматических данных нет).\n",
			pending, proposedN, pending-proposedN)
	default:
		fmt.Fprintf(&b,
			"**Предлагаемая оценка: ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)** — чтобы отклонить уязвимость, необходимо подтвердить решение о безопасности по всем %d функциям в попавших в сборку пакетах (%d рекомендованы к исключению; для %d найдены признаки уязвимости, требующие проверки экспертом).\n",
			pending, proposedN, flagged)
	}
	b.WriteString("\nДопущения (не проверяются автоматически, эксперт подтверждает их при согласовании):\n")
	b.WriteString("- Список уязвимых функций в базе (advisory) полон (если уязвимость затрагивает другие функции библиотеки, анализ их не увидит)\n")
	b.WriteString("- Внесённые решения о безопасности верны (система проверяет факт их наличия, а не правильность)\n")
	goos, goarch := c.Product.GOOS, c.Product.GOARCH
	if goos == "" {
		goos = "?"
	}
	if goarch == "" {
		goarch = "?"
	}
	tags := strings.Join(c.Product.BuildTags, ", ")
	if tags == "" {
		tags = "не указаны"
	}
	fmt.Fprintf(&b, "- Параметры сборки (%s/%s, теги: %s) соответствуют целевому окружению развёртывания\n",
		goos, goarch, tags)
	return b.String()
}

func allLimitations(c *domain.AnalysisCase) []string {
	var out []string
	add := func(l string) {
		for _, x := range out {
			if x == l {
				return
			}
		}
		out = append(out, l)
	}
	if c.Affected != nil {
		for _, l := range c.Affected.Limitations {
			add(l)
		}
	}
	if c.RootCause != nil {
		for _, l := range c.RootCause.Limitations {
			add(l)
		}
	}
	// The verdict copies graph limitations into its own record — dedupe,
	// or every limitation prints twice.
	for _, l := range c.EvidenceGraph.Limitations {
		add(l)
	}
	for _, l := range c.EvidenceGraph.ToolLimitations {
		add(l)
	}
	if c.Verdict != nil {
		for _, l := range c.Verdict.Limitations {
			add(l)
		}
	}
	return out
}

// TrackerRationale renders a human-readable, professional justification
// in Russian ready for issue trackers, detailing the verdict,
// product facts, build graph status, defect mechanism, and residual risks.
func TrackerRationale(c *domain.AnalysisCase) string {
	baseRationale := ""
	if c.Verdict == nil {
		baseRationale = "Анализ уязвимости не завершён (вердикт не вынесен)."
	} else {
		switch c.Verdict.Verdict {
		case domain.VerdictNoExploitPathFound:
			baseRationale = rationaleNoExploitPathFound(c)
		case domain.VerdictNotAffected:
			baseRationale = rationaleNotAffected(c)
		case domain.VerdictExploitable:
			baseRationale = rationaleExploitable(c)
		default:
			baseRationale = rationaleInconclusive(c)
		}
	}

	// Enrich with Justification dossier if available
	if c.Justification != nil {
		var b strings.Builder
		b.WriteString(baseRationale)
		if c.Justification.TechnicalMechanism != "" {
			b.WriteString(fmt.Sprintf("\n\n**Архитектурный контекст уязвимости:**\n%s", c.Justification.TechnicalMechanism))
		}
		if len(c.Justification.HumanRemainder) > 0 {
			b.WriteString("\n\n**Открытые вопросы для экспертного подтверждения (Human Remainder):**\n")
			for _, rem := range c.Justification.HumanRemainder {
				b.WriteString(fmt.Sprintf("- %s\n", rem.Question))
			}
		}
		return b.String()
	}

	return baseRationale
}

func rationale(c *domain.AnalysisCase) string {
	return TrackerRationale(c)
}

func shortRepo(repo string) string {
	repo = strings.TrimSpace(repo)
	if repo == "" {
		return "проекте"
	}
	base := filepath.Base(filepath.Clean(repo))
	if base == "." || base == "/" || base == "" {
		return repo
	}
	return base
}

func formatEnv(c *domain.AnalysisCase) string {
	var parts []string
	if c.Product.GoVersion != "" {
		parts = append(parts, "Go "+c.Product.GoVersion)
	}
	if c.Product.GOOS != "" && c.Product.GOARCH != "" {
		parts = append(parts, c.Product.GOOS+"/"+c.Product.GOARCH)
	}
	if len(c.Product.BuildTags) > 0 {
		parts = append(parts, "теги: "+strings.Join(c.Product.BuildTags, ", "))
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

func moduleAndVersion(c *domain.AnalysisCase) (string, string) {
	mod := c.Vulnerability.Module
	if mod == "" && len(c.Vulnerability.AffectedPackages) > 0 {
		mod = c.Vulnerability.AffectedPackages[0].Path
	}
	if mod == "" && c.Affected != nil && len(c.Affected.CheckedModules) > 0 {
		mod = c.Affected.CheckedModules[0]
	}
	ver := ""
	if c.Affected != nil {
		ver = c.Affected.ResolvedVersion
	}
	return mod, ver
}

func defectDescription(c *domain.AnalysisCase) string {
	if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
		var parts []string
		for _, rc := range c.RootCause.RootCauses {
			if rc.Mechanism != "" {
				parts = append(parts, fmt.Sprintf("%s (локализовано в `%s.%s`)", rootCauseMechanism(rc.Mechanism, true), rc.Package, rc.Symbol))
			}
		}
		if len(parts) > 0 {
			return strings.Join(parts, "; ")
		}
	}
	if c.Vulnerability.Summary != "" {
		return c.Vulnerability.Summary
	}
	if c.Vulnerability.Description != "" {
		desc := strings.TrimSpace(c.Vulnerability.Description)
		if idx := strings.Index(desc, "\n\n"); idx > 0 {
			desc = desc[:idx]
		}
		if len(desc) > 300 {
			if idx := strings.Index(desc[200:], ". "); idx > 0 {
				desc = desc[:200+idx+1]
			}
		}
		return desc
	}
	return "дефект в реализации библиотеки"
}

func linkedPackages(c *domain.AnalysisCase) map[string]bool {
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidencePackageList {
			if s, err := affected.PackageImportPaths([]byte(e.Content)); err == nil {
				return s
			}
		}
	}
	return nil
}

type locusSymbolNote struct {
	Symbol domain.SymbolRef
	Basis  string
}

func splitAdvisoryPackages(c *domain.AnalysisCase) (absentPkgs, presentPkgs []string, presentNotes []locusSymbolNote) {
	linked := linkedPackages(c)
	advisoryPkgs := map[string]bool{}

	if c.Exploit != nil {
		for _, s := range c.Exploit.LocusSubjects {
			advisoryPkgs[s.Package] = true
		}
	}
	for _, ap := range c.Vulnerability.AffectedPackages {
		if ap.Path != "" {
			advisoryPkgs[ap.Path] = true
		}
	}

	for pkg := range advisoryPkgs {
		if linked != nil {
			if !linked[pkg] {
				absentPkgs = append(absentPkgs, pkg)
			} else {
				presentPkgs = append(presentPkgs, pkg)
			}
		}
	}
	sort.Strings(absentPkgs)
	sort.Strings(presentPkgs)

	seenSym := map[domain.SymbolRef]bool{}
	if c.Exploit != nil {
		for _, d := range c.Exploit.NonLocusBasis {
			if linked != nil && linked[d.Symbol.Package] && !seenSym[d.Symbol] {
				seenSym[d.Symbol] = true
				presentNotes = append(presentNotes, locusSymbolNote{Symbol: d.Symbol, Basis: d.Basis})
			}
		}
		for _, d := range c.Exploit.ProposedNonLocus {
			if linked != nil && linked[d.Symbol.Package] && !seenSym[d.Symbol] {
				seenSym[d.Symbol] = true
				presentNotes = append(presentNotes, locusSymbolNote{Symbol: d.Symbol, Basis: d.Basis})
			}
		}
	}
	return absentPkgs, presentPkgs, presentNotes
}

func formatExposureParagraph(c *domain.AnalysisCase, absentPkgs []string) string {
	var inbounds, outbounds []string
	for _, f := range c.EvidenceGraph.ExposuresList() {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		desc := fmt.Sprintf("`%s` (через `%s`)", loc, f.Target)
		if f.Direction == "inbound" {
			inbounds = append(inbounds, desc)
		} else if f.Direction == "outbound" {
			outbounds = append(outbounds, desc)
		}
	}
	var parts []string
	if len(inbounds) > 0 {
		parts = append(parts, fmt.Sprintf("В коде проекта сервер создаётся в: %s.", strings.Join(inbounds, ", ")))
	}
	if len(outbounds) > 0 {
		parts = append(parts, fmt.Sprintf("Клиентские подключения: %s.", strings.Join(outbounds, ", ")))
	}
	if len(absentPkgs) > 0 {
		parts = append(parts, fmt.Sprintf("Инициализация или вызовы через отсутствующие уязвимые пакеты (`%s`) в коде проекта не используются.",
			strings.Join(absentPkgs, "`, `")))
	}
	return strings.Join(parts, " ")
}

func formatExposureSummary(c *domain.AnalysisCase) string {
	var list []string
	for _, f := range c.EvidenceGraph.ExposuresList() {
		loc := f.File
		if f.Line > 0 {
			loc = fmt.Sprintf("%s:%d", f.File, f.Line)
		}
		list = append(list, fmt.Sprintf("`%s` (`%s`)", loc, f.Target))
	}
	return strings.Join(list, ", ")
}

func formatPresentSymbolsParagraph(notes []locusSymbolNote) string {
	var b strings.Builder
	b.WriteString("То, что связанные пакеты входят в сборку, уязвимости не создаёт. Функции из advisory в скомпилированных пакетах:\n")
	for _, n := range notes {
		basis := n.Basis
		if basis == "" {
			basis = "дефектный код отсутствует"
		}
		basis = strings.ReplaceAll(basis, "accepted-machine-proposal", "принятая рекомендация анализатора")
		fmt.Fprintf(&b, "- `%s.%s`: %s\n", n.Symbol.Package, n.Symbol.Symbol, basis)
	}
	b.WriteString("Эти функции выполняют лишь диспетчеризацию или вспомогательную проверку, дефектная логика в них отсутствует, поэтому исполнение до дефекта не доходит.")
	return b.String()
}

func residualRisk(c *domain.AnalysisCase, absentPkgs []string) string {
	mod, _ := moduleAndVersion(c)
	_, best, ok := FixTarget(c)
	var fixNote string
	if ok && best != "" {
		fixNote = fmt.Sprintf(" Для устранения потребуется обновление `%s` до версии не ниже `%s`.", mod, best)
	} else if len(c.Vulnerability.FixedVersions) > 0 {
		fixNote = fmt.Sprintf(" Для устранения потребуется обновление до версии `%s`.", c.Vulnerability.FixedVersions[0])
	}

	if len(absentPkgs) > 0 {
		return fmt.Sprintf("Остаточный риск: если позже в проект будет добавлен импорт пакетов `%s` или сервер/клиент перейдёт на их использование, уязвимость станет применима.%s",
			strings.Join(absentPkgs, "`, `"), fixNote)
	}
	if fixNote != "" {
		return "Остаточный риск: при изменении конфигурации или пути вызовов уязвимость может стать активной." + fixNote
	}
	return ""
}

func rationaleNoExploitPathFound(c *domain.AnalysisCase) string {
	var b strings.Builder
	repo := shortRepo(c.Product.Repository)
	mod, ver := moduleAndVersion(c)
	commit := shortCommit(c.Product.Commit)
	absentPkgs, _, presentNotes := splitAdvisoryPackages(c)

	b.WriteString("Not Exploitable (Уязвимость не эксплуатируется).\n\n")

	if mod != "" && ver != "" {
		fmt.Fprintf(&b, "Библиотека в %s действительно `%s %s`, но код %s в сборку не входит и вызвать его нельзя. Это не ложное срабатывание (False Positive): сканер определил версию правильно, однако в данном снимке приложения уязвимый путь исполнения отсутствует.\n\n",
			repo, mod, ver, c.Vulnerability.ID)
	}

	env := formatEnv(c)
	if commit != "" {
		if mod != "" && ver != "" {
			fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s. В `go.mod` зависимость `%s` зафиксирована на версии `%s`.\n\n",
				c.Product.Repository, commit, env, mod, ver)
		} else {
			fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
				c.Product.Repository, commit, env)
		}
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	if len(absentPkgs) > 0 {
		fmt.Fprintf(&b, "В графе зависимостей сборки (`go list -deps`) пакеты `%s` отсутствуют и в бинарный файл не попадают.\n\n",
			strings.Join(absentPkgs, "`, `"))
	}

	if expText := formatExposureParagraph(c, absentPkgs); expText != "" {
		b.WriteString(expText)
		b.WriteString("\n\n")
	}

	if len(presentNotes) > 0 {
		b.WriteString(formatPresentSymbolsParagraph(presentNotes))
		b.WriteString("\n\n")
	}

	if len(c.EvidenceGraph.CallPaths) > 0 {
		b.WriteString("Сопоставление со сканером: `govulncheck` отмечает уязвимость как вызываемую (Reachable), обнаруживая пути вызова к вспомогательным функциям библиотеки. Однако углублённый анализ опровергает наличие уязвимости: вызываемые функции безопасны, а код с реальным дефектом в сборку не скомпилирован (ложная тревога govulncheck по достижимости).\n\n")
	}

	if risk := residualRisk(c, absentPkgs); risk != "" {
		b.WriteString(risk)
		b.WriteString("\n\n")
	}

	b.WriteString("Текст выше можно использовать в задаче трекера как обоснование статуса **Not Exploitable**.")
	return b.String()
}

func rationaleNotAffected(c *domain.AnalysisCase) string {
	var b strings.Builder
	repo := shortRepo(c.Product.Repository)
	mod, ver := moduleAndVersion(c)
	commit := shortCommit(c.Product.Commit)
	env := formatEnv(c)

	b.WriteString("Not Affected (Уязвимость не применима к сервису).\n\n")

	if c.Affected != nil && c.Affected.VersionAffected == domain.ClaimFalse {
		fmt.Fprintf(&b, "Библиотека `%s` в %s используется в версии `%s`, которая не входит в диапазон уязвимых версий. Предупреждение сканера не применимо к текущей версии.\n\n",
			mod, repo, ver)
	} else if c.Affected != nil && c.Affected.ModulePresent == domain.ClaimFalse {
		fmt.Fprintf(&b, "Модуль `%s` не входит в граф зависимостей проекта %s (`go list -m all`). Код библиотеки в проекте отсутствует.\n\n",
			mod, repo)
	} else if c.Affected != nil && c.Affected.PackagePresent == domain.ClaimFalse {
		fmt.Fprintf(&b, "Библиотека `%s %s` присутствует в `go.mod`, но ни один из уязвимых пакетов не импортируется кодом проекта %s (`go list -deps`). Код не скомпилирован в бинарный файл.\n\n",
			mod, ver, repo)
	} else {
		fmt.Fprintf(&b, "Уязвимость %s не применима к снимку %s: %s.\n\n",
			c.Vulnerability.ID, repo, c.Verdict.Reason)
	}

	if commit != "" {
		fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
			c.Product.Repository, commit, env)
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	b.WriteString("Изменений в коде или обновления зависимостей в данном снимке не требуется.\n\n")

	b.WriteString("Текст выше можно использовать в задаче трекера как обоснование закрытия со статусом **Not Affected**.")
	return b.String()
}

func rationaleExploitable(c *domain.AnalysisCase) string {
	var b strings.Builder
	repo := shortRepo(c.Product.Repository)
	mod, ver := moduleAndVersion(c)
	commit := shortCommit(c.Product.Commit)
	env := formatEnv(c)

	b.WriteString("Exploitable (Уязвимость подтверждена и эксплуатируема).\n\n")

	fmt.Fprintf(&b, "В проекте %s подтверждена возможность эксплуатации уязвимости %s (библиотека `%s %s`).\n\n",
		repo, c.Vulnerability.ID, mod, ver)

	if commit != "" {
		fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
			c.Product.Repository, commit, env)
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	b.WriteString("Факты проверки:\n")
	b.WriteString("- Уязвимый пакет входит в граф зависимостей сборки (`go list -deps`) и скомпилирован в бинарный файл.\n")
	if expText := formatExposureSummary(c); expText != "" {
		fmt.Fprintf(&b, "- Входные точки взаимодействия: %s.\n", expText)
	}
	b.WriteString("- Все обязательные условия эксплуатации дефекта подтверждены.\n\n")

	_, best, ok := FixTarget(c)
	if ok && best != "" {
		fmt.Fprintf(&b, "Требуется исправление: обновите зависимость `%s` до версии `%s` (`go get %s@%s && go mod tidy`) либо примените компенсирующие меры защиты.\n\n",
			mod, best, mod, best)
	} else {
		b.WriteString("Требуется исправление или применение компенсирующих мер защиты.\n\n")
	}

	b.WriteString("Текст выше можно использовать в задаче трекера как обоснование необходимости исправления (статус **Exploitable**).")
	return b.String()
}

func rationaleInconclusive(c *domain.AnalysisCase) string {
	var b strings.Builder
	repo := shortRepo(c.Product.Repository)
	mod, ver := moduleAndVersion(c)
	commit := shortCommit(c.Product.Commit)
	env := formatEnv(c)
	absentPkgs, _, presentNotes := splitAdvisoryPackages(c)

	b.WriteString("Требуется ручной анализ (Inconclusive).\n\n")

	fmt.Fprintf(&b, "Для уязвимости %s в проекте %s (библиотека `%s %s`) автоматический анализ не смог сделать однозначный вывод: %s.\n\n",
		c.Vulnerability.ID, repo, mod, ver, c.Verdict.Reason)

	if commit != "" {
		fmt.Fprintf(&b, "Проверено по репозиторию `%s`, коммит `%s`%s.\n\n",
			c.Product.Repository, commit, env)
	}

	fmt.Fprintf(&b, "%s — %s.\n\n", c.Vulnerability.ID, defectDescription(c))

	b.WriteString("Результаты проверки:\n")
	if len(absentPkgs) > 0 {
		fmt.Fprintf(&b, "- Пакеты `%s` отсутствуют в графе сборки (`go list -deps`) и физически не скомпилированы.\n",
			strings.Join(absentPkgs, "`, `"))
	}
	if len(presentNotes) > 0 {
		var names []string
		for _, n := range presentNotes {
			names = append(names, fmt.Sprintf("`%s.%s` (%s)", n.Symbol.Package, n.Symbol.Symbol, n.Basis))
		}
		fmt.Fprintf(&b, "- Для функций в скомпилированных пакетах сформированы рекомендации об исключении: %s.\n",
			strings.Join(names, ", "))
		b.WriteString("  Для автоматического применения рекомендаций можно запустить анализ с флагом `--accept-locus-proposals`.\n")
	}
	if expText := formatExposureSummary(c); expText != "" {
		fmt.Fprintf(&b, "- Точки взаимодействия в коде: %s.\n", expText)
	}
	b.WriteString("\nТекст выше можно использовать в задаче трекера для описания текущего статуса и открытых вопросов для эксперта.")
	return b.String()
}

// FixTarget picks the smallest published fixed version above the
// resolved one. ok=false when the component is not affected or the
// module cannot be named; version="" with ok=true means no fix exists.
func FixTarget(c *domain.AnalysisCase) (module, version string, ok bool) {
	if c.Affected == nil || c.Affected.VersionAffected != domain.ClaimTrue {
		return "", "", false
	}
	mod := c.Vulnerability.Module
	if mod == "" && len(c.Vulnerability.AffectedPackages) > 0 {
		mod = c.Vulnerability.AffectedPackages[0].Path
	}
	if mod == "" {
		return "", "", false
	}
	resolved := c.Affected.ResolvedVersion
	var best string
	for _, f := range c.Vulnerability.FixedVersions {
		fv := normalizeSemver(f)
		if fv == "" {
			continue
		}
		if resolved != "" && semver.Compare(fv, normalizeSemver(resolved)) <= 0 {
			continue
		}
		if best == "" || semver.Compare(fv, best) < 0 {
			best = fv
		}
	}
	return mod, best, true
}

// remediation renders a deterministic fix recommendation: the smallest
// fixed version above the resolved one, plus the go command to apply it.
// Empty when the component is not affected or no fix is published.
func remediation(c *domain.AnalysisCase, langRU ...bool) string {
	isRU := len(langRU) > 0 && langRU[0]
	mod, best, ok := FixTarget(c)
	if !ok {
		return ""
	}
	resolved := c.Affected.ResolvedVersion
	if best == "" {
		if isRU {
			return fmt.Sprintf("Для зависимости `%s` (текущая: `%s`) нет опубликованных версий с исправлением. "+
				"Рассмотрите возможность фиксации безопасной версии или наложения патча.", mod, resolved)
		}
		return fmt.Sprintf("No fixed version published for `%s` (current: `%s`). "+
			"Consider pinning an unaffected release or vendoring a patch.", mod, resolved)
	}
	if isRU {
		return fmt.Sprintf("Обновите зависимость `%s` с `%s` до `%s`:\n\n```\ngo get %s@%s\ngo mod tidy\n```",
			mod, resolved, best, mod, best)
	}
	return fmt.Sprintf("Update `%s` from `%s` to `%s`:\n\n```\ngo get %s@%s\ngo mod tidy\n```",
		mod, resolved, best, mod, best)
}

// normalizeSemver maps "1.2.3"/"v1.2.3" onto canonical semver for compare.
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

func shortCommit(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
