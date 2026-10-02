# Design: Report Structure Redesign (Inverted Pyramid)

- **Date:** 2026-10-02
- **Topic:** Redesign of `report.md` output structure to prioritize executive readability and actionable findings
- **Status:** Proposed

---

## 1. Context & Motivation

Currently, `internal/report/report.go` generates `report.md` by traversing internal analysis state sequentially from bottom to top:
1. Header & Verdict (1 line)
2. Affected analysis table
3. Root cause sinks
4. Exploit model & conditions
5. Exposure facts
6. Raw data flows (very verbose AST transformations)
7. Runtime facts
8. Claims table
9. Hypotheses & Reviews
10. Remediation
11. Tool executions table
12. Limitations
13. **Tracker-ready rationale (at the very bottom)**

This structure suffers from serious UX drawbacks for human readers (developers and AppSec specialists):
- The most crucial human-readable explanation (`Tracker-ready rationale`), which synthesizes the verdict and technical justification into plain Russian, is buried at line 150+ after complex AST graph dumps.
- Remediation commands are distant from the verdict.
- Verbose debugging details (Data flows, tool execution hashes, low-level parser limitations) distract from the primary decision.

---

## 2. Goals & Invariants

### Goals
1. **Executive Summary First:** The top of `report.md` must immediately present the Verdict, the Tracker Rationale (plain-Russian senior-analyst justification), and Remediation.
2. **Clear Evidence Dossier:** Deterministic verification results (Affected analysis, Claims, Exposure facts, Locus exclusions) are grouped into a clean middle section.
3. **Collapsible Technical Audit:** Verbose graph details (Data flows, Tool executions, Limitations, Review findings) are enclosed in a `<details><summary>` block, preserving 100% of auditability without cluttering default rendering.
4. **Zero Information Loss:** All existing compliance, observability, and audit guarantees (per `docs/agent-rules/observability.md`) remain fully intact in both `report.md` and `report.json`.

---

## 3. Detailed Structure of `report.md`

### Tier 1: Executive Summary (Immediate Visibility)
1. **Header & Context:**
   - `# Vulnerability analysis: <ID>`
   - Case ID, Repository, Commit, Toolchain (Go version, GOOS/GOARCH).
2. **Verdict Banner:**
   - `## Verdict: <VERDICT>`
   - Short reason blockquote: `> **<reason>**`
3. **Tracker Rationale / Executive Summary:**
   - `## Резюме для трекера / Обоснование`
   - Contains the senior-researcher Russian justification:
     - Clear conclusion (`Not Exploitable`, `Not Affected`, or `Exploitable`).
     - Why this is not a False Positive.
     - Why vulnerable code cannot be reached (e.g. absent packages in `go list -deps`, constructor differences).
     - Residual risk and boundary conditions.
4. **Remediation:**
   - `## Рекомендации по устранению` (if remediation is applicable)
   - Upgrade instructions (`go get ...@vX.Y.Z && go mod tidy`).

### Tier 2: Deterministic Evidence Dossier
5. **## Доказательная база (Evidence & Claims)**
   - `### Применимость (Affected Analysis)`: Table of probed/linked modules and packages.
   - `### Статус условий эксплуатации (Claims)`: Claims table (`C-LOCUS`, `C-REACH`, etc.) with verification and evidence links.
   - `### Точки входа (Exposure Facts)`: Table or list of network listeners (`net.Listen`, `grpc.NewServer`).
   - `### Экспертные и автономные решения (Locus & Sinks)`: Non-locus decisions (`HandleStreams`, `operateHeaders`) and machine recommendations.

### Tier 3: Technical Details & Audit (Collapsible)
6. **<details><summary><b>Технические детали и аудит (Data Flows, Tool Executions, Limitations)</b></summary>**
   - `### Потоки данных (Data Flows)`: Parameter flow origin and propagation chain.
   - `### Журнал инструментов (Tool Executions)`: Deterministic execution logs (exit code, duration, stdout sha256).
   - `### Ограничения анализа (Limitations)`: Analysis bounds and toolchain limitations.
   - `### Рецензирование (Review Findings)`: Semantic review issues, if any.
   - `### Факты среды (Runtime Facts)`: Environment snapshot and knowledge base digests.
   - `</details>`

---

## 4. Affected Components

1. `internal/report/report.go`:
   - Reorganize `Markdown(c *domain.AnalysisCase) string` to render sections in the new order.
   - Wrap Data Flows, Tool Executions, Limitations, Runtime Facts, and Review in `<details><summary>...</summary></details>`.
2. `internal/report/report_test.go`:
   - Update any tests asserting exact section order or headers in `report.md`.
   - Add dedicated test verifying the presence and order of the new sections and the collapsible details block.

---

## 5. Backward Compatibility & Test Verification

- `report.json`, `openvex.json`, `cyclonedx.json` are unchanged.
- `TrackerRationale` function contract remains unchanged; it is simply rendered near the top of `Markdown(c)`.
- All existing tests in `internal/report/...` and `cmd/analyzer/...` must pass cleanly.
