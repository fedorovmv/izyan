# B33: Contextual Severity & Triage Assessment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement backlog item B33, providing deterministic contextual risk assessment and triage re-ranking for CVEs (including nominal CVSS 10.0 / Blocker alerts) based on build closure, reachability, exposure (0.0.0.0 vs 127.0.0.1 vs none), authentication, and blast radius.

**Architecture:**
1. In `internal/domain/domain.go`, define `ContextualRisk`, `RiskFactors`, `RiskLevel`, `TriagePriority`, and `ContextualRiskStatus`. Extend `Vulnerability` with `BaseSeverity` and `BaseScore`.
2. In `internal/vulnerability/osv.go` and `internal/tracker/intake.go`, ingest CVSS vectors/scores and severity levels from OSV JSON and tracker tickets.
3. In `internal/risk/risk.go`, implement the deterministic `Assess` engine evaluating exposure facts (`EV-LISTENER`), authentication, and verdict to produce re-ranked priority (`P0..P3 / DISMISSED`), contextual score, SLA, and triage rationale.
4. In `internal/reporter/markdown.go`, `json.go`, and `cmd/izyan/main.go`, render the Triage Assessment block in Markdown reports, serialize `contextual_risk` in JSON, and print priority in CLI summaries.
5. Validate against autonomous and live corpora (`false-safe = 0`), sync gap-analysis and documentation, close B33.

**Tech Stack:** Go 1.22+, `internal/domain`, `internal/vulnerability`, `internal/tracker`, `internal/reporter`, `internal/risk`.

## Global Constraints
- Generality rule: NO case-specific strings, product names, or library package paths in production logic (`docs/agent-rules/generality.md`).
- Safety invariant: safe negative verdicts require a verified falsifier on a mandatory condition (`false-safe = 0`). Contextual risk demotions do NOT alter the underlying reachability verdict.
- Privacy rule: Zero internal corporate paths, repository names (`cloud-esb-micro`), or private credentials anywhere in tracked files or commit history.
- Testing economy: During intermediate tasks (Tasks 1-3), run ONLY fast targeted unit tests (`go test -run <Name> ./...`). The full corpus evaluation is reserved strictly for Task 4.
- Git policy: Commits are strictly local. Zero intermediate `git push`; push strictly once at the very end after whole-branch validation.

---

### Task 1: Domain Models for Contextual Risk & Ingestion

**Files:**
- Modify: `internal/domain/domain.go:60-80`, `internal/domain/domain.go:1130-1160`
- Modify: `internal/vulnerability/osv.go:20-30`, `internal/vulnerability/osv.go:130-160`
- Modify: `internal/tracker/intake.go:18-40`, `internal/tracker/intake.go:200-240`
- Modify: `cmd/izyan/main.go:315-345`
- Test: `internal/vulnerability/osv_test.go`
- Test: `internal/tracker/intake_test.go`

**Interfaces:**
- Produces: `domain.ContextualRisk`, `domain.RiskLevel`, `domain.TriagePriority`, `domain.ContextualRiskStatus`, `domain.RiskFactors`
- Produces: `v.BaseSeverity`, `v.BaseScore` on `domain.Vulnerability`
- Consumes: OSV `severity` array (`CVSS_V3`, `CVSS_V4`), `database_specific.severity`, Ticket `severity`, `cvss`.

- [ ] **Step 1: Write failing unit test in `internal/vulnerability/osv_test.go`**

```go
func TestParseOSV_SeverityAndCVSS(t *testing.T) {
	doc := []byte(`{
		"id": "GHSA-test-cvss-10",
		"summary": "Critical RCE",
		"database_specific": {
			"severity": "CRITICAL"
		},
		"severity": [
			{
				"type": "CVSS_V3",
				"score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
			}
		],
		"affected": [
			{
				"package": {"name": "example.com/vuln", "ecosystem": "Go"},
				"ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}]
			}
		]
	}`)
	v, err := ParseOSV(doc)
	if err != nil {
		t.Fatalf("ParseOSV failed: %v", err)
	}
	if v.BaseSeverity != "CRITICAL" {
		t.Fatalf("expected BaseSeverity CRITICAL, got %q", v.BaseSeverity)
	}
	if v.BaseScore != 9.8 {
		t.Fatalf("expected BaseScore 9.8, got %v", v.BaseScore)
	}
}
```

In `internal/tracker/intake_test.go`:
```go
func TestParseTicket_SeverityAndCVSS(t *testing.T) {
	text := `ticket: SEC-777
vulnerability: CVE-2026-9999
severity: BLOCKER
cvss: 10.0
`
	tickets, err := ParseTickets([]byte(text))
	if err != nil {
		t.Fatalf("ParseTickets failed: %v", err)
	}
	if len(tickets) != 1 {
		t.Fatalf("expected 1 ticket, got %d", len(tickets))
	}
	if tickets[0].Severity != "BLOCKER" {
		t.Fatalf("expected Severity BLOCKER, got %q", tickets[0].Severity)
	}
	if tickets[0].CVSS != "10.0" {
		t.Fatalf("expected CVSS 10.0, got %q", tickets[0].CVSS)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestParseOSV_SeverityAndCVSS|TestParseTicket_SeverityAndCVSS" ./internal/vulnerability ./internal/tracker`
Expected: FAIL (fields do not exist on structs).

- [ ] **Step 3: Implement domain types, OSV ingestion, and ticket parsing**

1. In `internal/domain/domain.go`:
   - Add `RiskLevel`, `TriagePriority`, `ContextualRiskStatus`, `ContextualRisk`, `RiskFactors` definitions.
   - Add `BaseSeverity string` and `BaseScore float64` to `Vulnerability`.
   - Add `ContextualRisk *ContextualRisk` to `Report`.
2. In `internal/vulnerability/osv.go`:
   - Add `Severity []osvSeverity json:"severity"` to `osvDocument`.
   - Add `Severity string json:"severity"` to `osvDatabaseSpecific`.
   - In `ParseOSV`, extract `v.BaseSeverity` from `doc.DatabaseSpecific.Severity` or `doc.Severity`.
   - Implement CVSS vector score parser `parseCVSSScore(vector string) float64` for CVSS 3.x and 4.0.
   - Assign `v.BaseScore`.
3. In `internal/tracker/intake.go`:
   - Add `Severity string json:"severity,omitempty"` and `CVSS string json:"cvss,omitempty"` to `Ticket`.
   - In `parseKeyValues`, recognize `"severity"` and `"cvss"`.
4. In `cmd/izyan/main.go`:
   - In `applyTicket`: if ticket provides severity/cvss, populate `caseVuln.BaseSeverity` and `caseVuln.BaseScore`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestParseOSV_SeverityAndCVSS|TestParseTicket_SeverityAndCVSS" ./internal/vulnerability ./internal/tracker`
Expected: PASS.
Run: `go test ./internal/vulnerability/... ./internal/tracker/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/domain/domain.go internal/vulnerability/ internal/tracker/ cmd/izyan/
git commit -m "feat(domain): add ContextualRisk models and base severity ingestion from OSV/tickets"
```

---

### Task 2: Contextual Risk & Triage Engine (`internal/risk`)

**Files:**
- Create: `internal/risk/risk.go`
- Create: `internal/risk/risk_test.go`

**Interfaces:**
- Consumes: `domain.Vulnerability`, `*domain.AnalysisCase`, `domain.VerdictResult`
- Produces: `domain.ContextualRisk` via `risk.Assess(v domain.Vulnerability, c *domain.AnalysisCase, vr domain.VerdictResult) domain.ContextualRisk`

- [ ] **Step 1: Write comprehensive unit tests in `internal/risk/risk_test.go`**

Test all 5 rules from the spec:
1. `TestAssess_NotAffected_Dismissed`: Base 10.0, verdict `NOT_AFFECTED` -> `PriorityDismissed`, `RiskLevelNone`, `ContextualScore: 0.0`.
2. `TestAssess_NoExploitPath_Dismissed`: Base 10.0, verdict `NO_EXPLOIT_PATH_FOUND` -> `PriorityDismissed`, `RiskLevelNone`, `ContextualScore: 0.0`.
3. `TestAssess_Exploitable_PublicUnauth_BlockerP0`: Base 10.0, verdict `EXPLOITABLE`, listener `0.0.0.0:8080`, unauth -> `PriorityP0`, `RiskLevelCritical`, `ContextualScore: 10.0`, SLA "24h (Immediate)".
4. `TestAssess_Exploitable_PublicAuth_P1`: Base 10.0, verdict `EXPLOITABLE`, listener `0.0.0.0:8080`, auth required -> `PriorityP1`, `RiskLevelHigh`, `ContextualScore: 7.5`, SLA "7d".
5. `TestAssess_Exploitable_InternalLoopback_P2`: Base 10.0, verdict `EXPLOITABLE`, listener `127.0.0.1:9090` -> `PriorityP2`, `RiskLevelMedium`, `ContextualScore: 4.5`, SLA "Sprint (30d)".
6. `TestAssess_Exploitable_NoListeners_P2`: Base 10.0, verdict `EXPLOITABLE`, no listeners (CLI tool) -> `PriorityP2`, `RiskLevelMedium`, `ContextualScore: 4.5`.
7. `TestAssess_Inconclusive_CriticalBase_P1Provisional`: Base 10.0, verdict `INCONCLUSIVE` -> `PriorityP1`, `RiskLevelHigh`, Status `PROVISIONAL`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/risk`
Expected: FAIL (package `risk` does not exist).

- [ ] **Step 3: Implement `internal/risk/risk.go`**

1. Create package `risk`.
2. Implement listener extraction helper `detectExposure(c *domain.AnalysisCase) (exposure string, listenerDetails []string)`.
   - Inspects `c.EvidenceGraph` evidence of kind `EvidenceListener` or parse AST listener descriptions.
   - If any listener is `0.0.0.0`, `:port`, or wildcard -> `exposure = "PUBLIC"`.
   - If all listeners are `127.0.0.1`, `localhost`, `::1` -> `exposure = "INTERNAL"`.
   - If no listeners -> `exposure = "NONE"`.
3. Implement `detectAuthentication(c *domain.AnalysisCase) string`.
   - Checks if any claim or condition verified authentication (`AUTHENTICATED` / `domain.ConditionAuthentication`).
4. Implement `Assess(v domain.Vulnerability, c *domain.AnalysisCase, vr domain.VerdictResult) domain.ContextualRisk`:
   - Follow Rules 1..5 strictly from spec §4.
   - Generate rich, human-readable `AdjustmentReason` explaining the triage decision and citing specific listeners/addresses.

- [ ] **Step 4: Run unit tests to verify they pass**

Run: `go test -v ./internal/risk`
Expected: PASS (all tests pass).

- [ ] **Step 5: Commit**

```bash
git add internal/risk/
git commit -m "feat(risk): implement contextual risk assessment and triage engine"
```

---

### Task 3: Integration in Report Generator & CLI

**Files:**
- Modify: `internal/reporter/markdown.go:80-160`
- Modify: `internal/reporter/json.go:20-50`
- Modify: `internal/orchestrator/orchestrator.go:200-240` (or where `Report` is built)
- Modify: `cmd/izyan/main.go:450-520`
- Test: `internal/reporter/markdown_test.go`
- Test: `internal/reporter/json_test.go`

**Interfaces:**
- Consumes: `risk.Assess`
- Produces: `## Контекстная критичность и триаж (Triage Assessment)` in `report.md`, `"contextual_risk"` in `report.json`, priority string in CLI eval output.

- [ ] **Step 1: Write failing test in `internal/reporter/markdown_test.go` and `json_test.go`**

In `internal/reporter/markdown_test.go`:
```go
func TestRenderMarkdown_ContextualRisk(t *testing.T) {
	rep := domain.Report{
		Vulnerability: domain.Vulnerability{ID: "CVE-2026-1234"},
		Verdict: domain.VerdictResult{Verdict: domain.VerdictNoExploitPath},
		ContextualRisk: &domain.ContextualRisk{
			Status: domain.RiskStatusAssessed,
			BaseSeverity: "CRITICAL",
			BaseScore: 10.0,
			ContextualLevel: domain.RiskLevelNone,
			ContextualScore: 0.0,
			Priority: domain.PriorityDismissed,
			SLA: "None (No remediation required)",
			AdjustmentReason: "Обязательное условие эксплуатации опровергнуто.",
		},
	}
	md := RenderMarkdown(rep)
	if !strings.Contains(md, "## Контекстная критичность и триаж") {
		t.Fatalf("expected markdown to contain triage section, got: %s", md)
	}
	if !strings.Contains(md, "DISMISSED") {
		t.Fatalf("expected markdown to contain DISMISSED priority")
	}
}
```

In `internal/reporter/json_test.go`:
Verify `rep.ContextualRisk` is serialized in JSON output.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestRenderMarkdown_ContextualRisk" ./internal/reporter`
Expected: FAIL.

- [ ] **Step 3: Integrate `risk.Assess` into orchestrator, report generators, and CLI**

1. In orchestrator / report builder (where `domain.Report` is constructed):
   - Call `rep.ContextualRisk = risk.Assess(rep.Vulnerability, c, rep.Verdict)`.
2. In `internal/reporter/markdown.go`:
   - Add `renderContextualRisk(rep domain.Report) string` right after Verdict.
   - Render the table and blockquote with adjustment rationale from spec §5.1.
3. In `internal/reporter/json.go`:
   - Ensure `ContextualRisk` field is included in report JSON structure.
4. In `cmd/izyan/main.go` and eval runner:
   - When printing case summary line, if `ContextualRisk != nil`:
     Include `priority: P... (Level, SLA: ...)`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v ./internal/reporter/...`
Expected: PASS.
Run: `go test ./internal/risk/... ./internal/reporter/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/reporter/ internal/orchestrator/ cmd/izyan/
git commit -m "feat(reporter): render contextual risk and triage assessment in reports and CLI"
```

---

### Task 4: Corpus Validation, Baseline & Docs Sync (closing B33)

**Files:**
- Modify: `docs/dev/gap-analysis.md` (close B33 in §1, remove from §2)
- Modify: `eval/README.md` (document contextual severity and triage assessment)
- Move: `docs/dev/specs/2026-10-05-contextual-severity-triage-design.md` -> `docs/dev/history/features/2026-10-05-contextual-severity-triage-design.md`
- Remove: `docs/dev/plans/2026-10-05-contextual-severity-triage-plan.md`

- [ ] **Step 1: Run targeted single case evaluation**

Run:
```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json --case real-yaml-file
```
Verify that output contains `priority: DISMISSED` and report has `## Контекстная критичность и триаж`.

- [ ] **Step 2: Run full 38-case evaluation on autonomous corpus**

Command:
```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
```
Expected: 38/38 PASS, 0 fail, false-safe = 0.

- [ ] **Step 3: Run standard hygiene checks**

Commands:
```bash
gofmt -l .
go vet ./...
go test ./...
```
Expected: 0 errors, all tests pass.

- [ ] **Step 4: Update documentation and gap analysis**

- In `docs/dev/gap-analysis.md`: delete B33 from §2, add closing entry in §1.
- In `eval/README.md`: add section on Contextual Severity & Triage Assessment.
- Archive design spec to `docs/dev/history/features/` and remove temporary plan.

- [ ] **Step 5: Commit**

```bash
git commit -m "docs: close B33 and document contextual severity and triage assessment"
```
