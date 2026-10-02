# Report Clarity, Humanization, and Provenance Breakdown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Eliminate all internal jargon (`non_locus`, raw `TRUE`/`FALSE`, `advisory-listed affected symbol`), remove `<details>` wrapping, add clear `govulncheck` reporting, and provide a transparent breakdown between Deterministic Compiler verification and LLM research.

**Architecture:** Update `internal/report/report.go` to localize table booleans, replace internal locus headings with human-friendly descriptions, add `govulncheckStatus` helper and `renderProvenanceBreakdown` section, and render technical audit as a standard `##` markdown section without `<details>`. Add comprehensive unit tests in `internal/report/report_test.go`.

**Tech Stack:** Go 1.26 standard library.

## Global Constraints

- Verdict Safety: No changes to verdict evaluation logic or safety guarantees.
- Full Audit Preservation: All audit data must remain intact in `report.md`, `report.en.md`, and `report.json`.
- Zero internal corporate paths, names, or credentials in tracked files or tests.
- All code must pass `gofmt`, `go vet ./...`, and `go test ./...`.

---

### Task 1: Add Unit Tests for Humanized Report and Provenance Breakdown (TDD Red)

**Files:**
- Test: `internal/report/report_test.go`

**Interfaces:**
- Consumes: `report.Markdown(c *domain.AnalysisCase, lang ...string) string`
- Produces: Test assertions validating:
  1. No occurrences of `<details>` or `<summary>` in `Markdown(c)`.
  2. Russian Affected table uses `Да` / `Нет`, not raw `TRUE` / `FALSE`.
  3. Russian Claims table uses `Подтверждено (TRUE)` / `Опровергнуто (FALSE)`.
  4. Russian non-locus section uses `#### Функции без дефекта (исключены из анализа уязвимости)`.
  5. Russian root causes use `заявлена как уязвимая в базе (advisory)`.
  6. Provenance breakdown section `### Источники и методы проверки` exists and lists deterministic vs LLM checks.
  7. Govulncheck status is displayed in Affected Analysis / Evidence Dossier.

- [ ] **Step 1: Write failing unit test `TestReportClarityAndProvenance` in `internal/report/report_test.go`**

Add test asserting the humanized phrases and absence of `<details>`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/report -run TestReportClarityAndProvenance`
Expected: FAIL

---

### Task 2: Implement Humanization, Provenance Breakdown, and Remove `<details>` (TDD Green)

**Files:**
- Modify: `internal/report/report.go`

**Interfaces:**
- `Markdown(c *domain.AnalysisCase, lang ...string) string`

- [ ] **Step 1: Implement changes in `internal/report/report.go`**

1. Helper `localizeClaimResult(r domain.ClaimResult, isRU bool) string`:
   - Returns `Да (выполняется)` / `Подтверждено (TRUE)` if true, `Нет (опровергнуто)` / `Опровергнуто (FALSE)` if false, `Не определено (UNKNOWN)` if unknown.
2. Helper `localizeAffectedBool(b domain.ClaimResult, isRU bool) string`:
   - Returns `Да` if true, `Нет` if false, `Не определено` if unknown.
3. Helper `govulncheckSummary(c *domain.AnalysisCase, isRU bool) string`:
   - Checks `c.EvidenceGraph` for govulncheck evidence and returns human-readable summary.
4. Add govulncheck row to Affected Analysis table.
5. In Root Causes: replace `advisory-listed affected symbol` with `заявлена как уязвимая в базе (advisory)` when `isRU`.
6. In Non-locus:
   - Header: `#### Функции без дефекта (исключены из анализа уязвимости)`.
   - Text: `Функции из базы уязвимости (advisory), которые признаны безопасными (являются вспомогательными диспетчерами или проверками входных данных) и не содержат дефектной операции:`.
   - Notes: replace `accepted-machine-proposal` with `принятая рекомендация анализатора`.
7. Add Provenance Breakdown subsection:
   - `### Источники и методы проверки (Методология)`:
     - ⚙️ Детерминированные проверки компилятора Go (`go list -deps`, `govulncheck`, AST).
     - 🤖 Семантический анализ LLM (архитектура дефекта, семантическое ревью).
8. Remove `<details>` and `<summary>`:
   - Replace with `## Технические детали и аудит (Data Flows, Tool Executions, Limitations)` (RU) / `## Technical Details & Audit (Data Flows, Tool Executions, Limitations)` (EN).

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test -v ./internal/report`
Expected: ALL PASS

---

### Task 3: Full Suite Verification & Regeneration of Real Case Reports

- [ ] **Step 1: Format and vet codebase**

Run: `gofmt -w cmd/ internal/ && go vet ./...`

- [ ] **Step 2: Run complete test suite**

Run: `go test ./...`
Expected: ALL PASS

- [ ] **Step 3: Regenerate reports for `GO-2026-6443`**

Update `.vuln-analyzer/verified-test2/GO-2026-6443-1790927532/report.md` and `report.en.md` and verify output.
