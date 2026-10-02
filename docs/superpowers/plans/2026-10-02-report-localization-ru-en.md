# Report Localization (RU/EN) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement full Russian localization for `report.md`, dual generation of English `report.en.md`, and support the `--lang=ru|en` CLI flag.

**Architecture:** Extend `internal/report/report.go` to provide localized rendering (`lang="ru"` by default, `"en"` for English). Introduce translation dictionaries for verdict reasons, affected analysis table checks, claim verification labels, and standard exploit condition descriptions. Update `report.Write` to generate both `report.md` (Russian) and `report.en.md` (English). Add `--lang` flag to `cmd/analyzer/main.go`.

**Tech Stack:** Go 1.26 standard library.

## Global Constraints

- Verdict Safety: No changes to verdict evaluation logic or safety guarantees.
- Full Audit Preservation: All audit data must remain intact in both RU and EN outputs.
- Zero internal corporate paths, names, or credentials in tracked files or tests.
- All code must pass `gofmt`, `go vet ./...`, and `go test ./...`.

---

### Task 1: Add Unit Tests for RU and EN Markdown Report Rendering (TDD Red)

**Files:**
- Test: `internal/report/report_test.go`

**Interfaces:**
- Consumes: `report.Markdown(c *domain.AnalysisCase, lang ...string) string`, `report.Write(dir string, c *domain.AnalysisCase) error`
- Produces: Tests asserting RU phrases in `report.md`, EN phrases in `report.en.md`, and dual-file generation by `Write`.

- [ ] **Step 1: Write the failing tests in `internal/report/report_test.go`**

Add tests:
- `TestMarkdownLocalizationRU`:
  - Asserts `# Анализ уязвимости: ...`
  - Asserts `## Вердикт: `NO_EXPLOIT_PATH_FOUND``
  - Asserts `> **Обязательное условие эксплуатации опровергнуто (уязвимый путь исполнения отсутствует)**`
  - Asserts `## Резюме`
  - Asserts `## Рекомендации по устранению`
  - Asserts `| Наличие модуля в зависимостях |`
  - Asserts `| Уязвимый пакет входит в сборку |`
  - Asserts `<details>` and `<summary><b>Технические детали и аудит`
- `TestMarkdownLocalizationEN`:
  - Asserts `# Vulnerability analysis: ...`
  - Asserts `## Verdict: `NO_EXPLOIT_PATH_FOUND``
  - Asserts `> **mandatory exploit condition is proven false**`
  - Asserts `## Executive Summary`
  - Asserts `## Remediation`
  - Asserts `| module present |`
  - Asserts `| package present |`
  - Asserts `<details>` and `<summary><b>Technical Details & Audit`
- `TestReportWriteGeneratesBothRUandEN`:
  - Calls `Write(tmpDir, c)` and verifies both `report.md` and `report.en.md` exist and contain their respective localized content.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/report -run TestMarkdownLocalization`
Expected: FAIL because RU localization and dual writing are not implemented yet.

---

### Task 2: Implement RU & EN Localization and Dual Generation in `internal/report/report.go` (TDD Green)

**Files:**
- Modify: `internal/report/report.go`

**Interfaces:**
- `Markdown(c *domain.AnalysisCase, lang ...string) string`
- `Write(dir string, c *domain.AnalysisCase) error`

- [ ] **Step 1: Implement translation dictionaries and localized markdown builder**

In `internal/report/report.go`:
- Define helper functions:
  - `localizeVerdictReason(reason string, lang string) string`
  - `localizeCheck(check string, lang string) string`
  - `localizeCondition(c domain.Condition, lang string) string`
  - `localizeVerification(v string, lang string) string`
- Update `Markdown(c *domain.AnalysisCase, lang ...string) string`:
  - Determine language (`"ru"` by default, `"en"` if requested).
  - Use `## Резюме` for RU, `## Executive Summary` for EN.
  - Translate table checks and condition descriptions when `lang == "ru"`.
- Update `Write(dir string, c *domain.AnalysisCase) error`:
  - Write `report.md` using `Markdown(c, "ru")`
  - Write `report.en.md` using `Markdown(c, "en")`
  - Write `report.json`, `openvex.json`, `cyclonedx.json` as before.

- [ ] **Step 2: Run tests to verify they pass**

Run: `go test -v ./internal/report`
Expected: ALL PASS

---

### Task 3: Support `--lang` Flag in CLI (`cmd/analyzer/main.go`)

**Files:**
- Modify: `cmd/analyzer/main.go`
- Test: `cmd/analyzer/main_test.go`

- [ ] **Step 1: Add `--lang` flag to analyzer CLI**

Add `--lang` flag (default `"ru"`, accepts `"ru"` or `"en"`):
- Pass to tracker publication or console logging if applicable.
- Ensure `--help` documents `--lang`.

- [ ] **Step 2: Run CLI tests**

Run: `go test -v ./cmd/analyzer/...`
Expected: PASS

---

### Task 4: Full Suite Verification & Inspection

- [ ] **Step 1: Format and vet codebase**

Run: `gofmt -w cmd/ internal/ && go vet ./...`

- [ ] **Step 2: Run complete test suite**

Run: `go test ./...`
Expected: ALL PASS

- [ ] **Step 3: Regenerate reports for `GO-2026-6443`**

Verify that both `report.md` (RU) and `report.en.md` (EN) are generated and formatted cleanly.
