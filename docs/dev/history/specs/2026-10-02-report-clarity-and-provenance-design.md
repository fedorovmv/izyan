# Design: Report Clarity, Humanization, and Provenance Breakdown

- **Date:** 2026-10-02
- **Topic:** Complete elimination of internal jargon (`non_locus`, raw `TRUE`/`FALSE`, `advisory-listed affected symbol`), removal of `<details>` wrapping, explicit `govulncheck` reporting, and clean separation between Deterministic and LLM-derived findings.
- **Status:** Proposed

---

## 1. Context & Motivation

While earlier iterations introduced the Inverted Pyramid layout and Russian localization, several friction points remain for human readers:
1. **Cryptic Jargon:** Terms like `Экспертные решения non_locus` and `advisory-listed affected symbol` are internal developer/researcher jargon that confuse AppSec analysts and product developers.
2. **Raw Booleans:** Tables display raw `TRUE`, `FALSE`, and `UNKNOWN`.
3. **Broken Rendering of `<details>`:** In various ticket trackers, Jira, GitLab, and Markdown previewers, HTML `<details><summary>` blocks render poorly or display broken markup.
4. **Missing Govulncheck Callout:** Although `govulncheck` is executed and audited, its high-level finding (e.g. no call path found in source code) is not surfaced clearly in the main evidence dossier.
5. **Ambiguous Finding Provenance:** Readers cannot easily distinguish what was verified with mathematical certainty by the Go compiler (`go list -deps`, AST, `govulncheck`) versus what was deduced by the LLM (patch architecture research, semantic review).

---

## 2. Requirements & Changes

### 2.1. Terminology Humanization
- **Replace `non_locus`:**
  - Header: `#### Функции без дефекта (исключены из анализа уязвимости)`
  - Description: *Функции из базы уязвимости (advisory), которые признаны безопасными (являются вспомогательными диспетчерами или проверками входных данных) и не содержат дефектной операции.*
  - Symbol notes: replace `accepted-machine-proposal` with `принятая рекомендация анализатора`.
- **Replace raw `TRUE` / `FALSE` / `UNKNOWN`:**
  - In Affected Analysis table:
    - `TRUE` -> `Да`
    - `FALSE` -> `Нет`
    - `UNKNOWN` -> `Не определено`
  - In Claims table:
    - `TRUE` -> `Подтверждено (TRUE)`
    - `FALSE` -> `Опровергнуто (FALSE)`
    - `UNKNOWN` -> `Не определено (UNKNOWN)`
- **Replace `advisory-listed affected symbol`:**
  - Localized: `заявлена как уязвимая в базе (advisory)`.

### 2.2. Elimination of `<details>` and `<summary>`
- Remove all `<details>` and `<summary>` tags.
- Audit sections are rendered under standard Markdown headers:
  - `## Технические детали и аудит` (RU) / `## Technical Details & Audit` (EN)
  - Subsections: `### Потоки данных (Data Flows)`, `### Журнал инструментов (Tool Executions)`, `### Ограничения анализа (Limitations)`, `### Рецензирование (Review Findings)`, `### Факты среды (Runtime Facts)`.

### 2.3. Govulncheck Status in Evidence Dossier
- In the **Применимость (Affected Analysis)** table or Evidence Dossier, display the govulncheck status:
  - Row: `| Статический анализ вызовов (govulncheck) | Трасса вызовов до уязвимого кода не обнаружена |`
  - If call path exists: display call path details.

### 2.4. Clear Division: Deterministic Compiler vs. LLM Research
- In `## Доказательная база`, add a dedicated section:
  - `### Источники и методы проверки (Методология)`:
    - ⚙️ **Детерминированные проверки компилятора Go:**
      - **Зависимости (`go.mod` / `go list -m`):** библиотека `google.golang.org/grpc` зафиксирована на версии `v1.83.0` (входит в уязвимый диапазон).
      - **Граф сборки (`go list -deps`):** пакет `google.golang.org/grpc/internal/xds/server` **физически отсутствует** в бинарном файле.
      - **Статический анализ вызовов (`govulncheck`):** трасса вызовов от кода продукта до уязвимого кода не найдена.
      - **Анализ точек входа (AST):** сервер инициализируется в `main.go:22` через безопасный стандартный конструктор `grpc.NewServer`.
    - 🤖 **Семантический анализ LLM (AI-исследование):**
      - **Архитектурный анализ уязвимости:** разбор фикс-коммита и кода gRPC выявил, что дефект (паника из-за `authority[0]`) локализован исключительно в xDS routing interceptor (`RouteAndProcess`), тогда как `HandleStreams` и `operateHeaders` являются безопасными диспетчерами.
      - **Семантическое рецензирование (Review):** подтверждено, что gRPC сервер без xDS не выполняет уязвимую операцию.
    - 🛡️ **Итоговый вердикт:**
      - Сформулирован **детерминированно**: после исключения доказанно вспомогательных функций единственный сайт дефекта физически отсутствует в бинарном файле сборки.

---

## 3. Implementation Scope

1. `internal/report/report.go`:
   - Add `govulncheckStatus(c *domain.AnalysisCase, isRU bool) string`.
   - Add `renderProvenanceBreakdown(b *strings.Builder, c *domain.AnalysisCase, isRU bool)`.
   - Update `localizeClaimResult(r domain.ClaimResult, isRU bool) string`.
   - Update `localizeAffectedBool(b domain.ClaimResult, isRU bool) string`.
   - Remove `<details>` and `</details>` tags; replace with standard `##` header.
   - Update locus headers and replace `advisory-listed affected symbol`.
2. `internal/report/report_test.go`:
   - Update assertions for the new section headers, govulncheck callout, and localized values.
   - Verify both RU and EN output formats.
