# B18: Snapshot/Toolchain Platform Conditions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement backlog item B18 (Defect D3), enabling detection and evaluation of Go toolchain/platform conditions from binary metadata, tickets (including LLM intake), or CLI flags, resolving `ghsa-33mj-cw25-m34h` on the reference product to its true verdict: `NO_EXPLOIT_PATH_FOUND` (0 fail, 0 false-safe).

**Architecture:** 
1. In `internal/tracker/`, add Go toolchain support to `Ticket`, the deterministic ticket parser, and `llm_intake.go` (extracting `go_version` with anti-hallucination validation). In `cmd/izyan/main.go`, propagate ticket toolchain version to `opts.ReleaseGoVersion`.
2. In `internal/exploit/classify.go`, introduce `ClassCryptoDowngrade` for CWE-326, 327, 757 and TLS downgrade keywords, fixing defect D3 (misclassification as `INFO_LEAK`).
3. In `internal/exploit/patterns.go` and `builder.go`, register an exploit pattern for `ClassCryptoDowngrade` with a mandatory `C-PLATFORM` (`PLATFORM_CONDITION`) requiring `go_version < 1.18`.
4. `evaluator.Platform` and `verifySnapshotFalse` in `negative.go` evaluate and verify `C-PLATFORM` against the product snapshot Go version, proving `FALSE` when Go >= 1.18.

**Tech Stack:** Go 1.22+, `golang.org/x/mod/semver`, `internal/exploit`, `internal/evaluator`, `internal/tracker`, `internal/domain`.

## Global Constraints
- Generality rule: NO case-specific strings, product names, or library package paths (no `amqp091`, `cloud-esb`, etc.) in production logic in `internal/exploit/`, `internal/evaluator/`, or `internal/goanalysis/` (`docs/agent-rules/generality.md`).
- Safety invariant: safe negative verdicts require a verified falsifier on a mandatory condition (`false-safe = 0`).
- Privacy rule: Zero internal corporate paths, repository names (`cloud-esb-micro`), or private credentials anywhere in tracked files or commit history.
- Testing economy: During intermediate tasks (Tasks 1-3), run ONLY fast targeted unit tests (`go test -run <Name> ./...`). The full corpus evaluation is reserved strictly for Task 4.
- Git policy: Commits are strictly local. Zero intermediate `git push`; push strictly once at the very end after whole-branch validation.

---

### Task 1: Intake & Ticket Go Version Support

**Files:**
- Modify: `internal/tracker/intake.go:18-36`, `internal/tracker/intake.go:200-240`
- Modify: `internal/tracker/llm_intake.go:15-46`, `internal/tracker/llm_intake.go:70-115`
- Modify: `cmd/izyan/main.go:316-335`
- Test: `internal/tracker/intake_test.go`
- Test: `internal/tracker/llm_intake_test.go`

**Interfaces:**
- Consumes: `domain.ProductSnapshot.ReleaseGoVersion`, `toolaudit.Run`
- Produces: `Ticket.GoVersion`, `Ticket.Toolchain`, LLM intake extraction of `go_version` into `o.releaseGo` / `opts.ReleaseGoVersion`.

- [ ] **Step 1: Write failing tests in `internal/tracker/intake_test.go` and `llm_intake_test.go`**

In `internal/tracker/intake_test.go`, test key-value extraction of Go version:
```go
func TestParseTicket_GoVersion(t *testing.T) {
	text := `ticket: SEC-888
vulnerability: CVE-2026-77405
package: github.com/rabbitmq/amqp091-go
go_version: go1.22.5
`
	tickets, err := ParseTickets([]byte(text))
	if err != nil {
		t.Fatalf("ParseTickets failed: %v", err)
	}
	if len(tickets) != 1 {
		t.Fatalf("expected 1 ticket, got %d", len(tickets))
	}
	if tickets[0].GoVersion != "go1.22.5" {
		t.Fatalf("expected GoVersion go1.22.5, got %q", tickets[0].GoVersion)
	}
}
```

In `internal/tracker/llm_intake_test.go`, test LLM extraction of Go version:
```go
func TestExtractTicketWithLLM_WithGoVersion(t *testing.T) {
	rawText := `В задаче SEC-999 для сервиса AUTH обнаружена CVE-2026-77405 в amqp091-go v1.10.0. Сервис собран на Go 1.22.4.`
	mockResp := `{
		"vulnerability": "CVE-2026-77405",
		"ticket_id": "SEC-999",
		"package": "github.com/rabbitmq/amqp091-go",
		"version": "v1.10.0",
		"component": "AUTH",
		"go_version": "go1.22.4",
		"summary": "TLS min version weakness in amqp"
	}`
	completer := mockCompleter{response: mockResp}
	tk, err := ExtractTicketWithLLM(context.Background(), completer, rawText)
	if err != nil {
		t.Fatalf("ExtractTicketWithLLM failed: %v", err)
	}
	if tk.GoVersion != "go1.22.4" {
		t.Fatalf("expected GoVersion go1.22.4, got %q", tk.GoVersion)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -v -run "TestParseTicket_GoVersion|TestExtractTicketWithLLM_WithGoVersion" ./internal/tracker`
Expected: FAIL (fields `GoVersion` does not exist on `Ticket`).

- [ ] **Step 3: Implement `GoVersion` and `Toolchain` in `intake.go`, `llm_intake.go`, and `cmd/izyan/main.go`**

In `internal/tracker/intake.go`:
- Add `GoVersion string json:"go_version,omitempty"` and `Toolchain string json:"toolchain,omitempty"` to `Ticket`.
- In `parseKeyValues`, add cases for `"go_version"`, `"go-version"`, `"go version"`, `"toolchain"` to assign `t.GoVersion`.

In `internal/tracker/llm_intake.go`:
- Add `"go_version": "<Go toolchain or compiler version, e.g. go1.22.4, 1.21, if mentioned>"` to `ticketExtractorSystemPrompt`.
- Add `GoVersion string json:"go_version"` to `llmTicketExtraction`.
- In `ExtractTicketWithLLM`, validate `ext.GoVersion` and assign `t.GoVersion = cleanGoVersion(ext.GoVersion)`. Ensure anti-hallucination check verifies that version string was mentioned in `rawText`.

In `cmd/izyan/main.go`:
- In `applyTicket`:
  ```go
  if o.releaseGo == "" {
      if t.GoVersion != "" {
          o.releaseGo = t.GoVersion
      } else if t.Toolchain != "" {
          o.releaseGo = t.Toolchain
      }
  }
  ```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -v -run "TestParseTicket_GoVersion|TestExtractTicketWithLLM_WithGoVersion" ./internal/tracker`
Expected: PASS.
Run: `go test ./internal/tracker/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/tracker/ cmd/izyan/
git commit -m "feat(tracker): support Go toolchain version in ticket parsing and LLM intake"
```

---

### Task 2: Classification of Crypto & TLS Downgrade (`ClassCryptoDowngrade`)

**Files:**
- Modify: `internal/exploit/classify.go:16-35`, `internal/exploit/classify.go:48-64`, `internal/exploit/classify.go:68-88`
- Test: `internal/exploit/classify_test.go`

**Interfaces:**
- Consumes: `domain.Vulnerability`, `fix.Patch`
- Produces: `ClassCryptoDowngrade`, mapping for CWE-326, 327, 757 and TLS downgrade keywords.

- [ ] **Step 1: Write failing test in `internal/exploit/classify_test.go`**

Add test verifying `GHSA-33mj` is classified as `ClassCryptoDowngrade` (not `ClassInfoLeak`):
```go
func TestClassify_CryptoDowngrade(t *testing.T) {
	v := domain.Vulnerability{
		ID:      "GHSA-33mj-cw25-m34h",
		Summary: "RabbitMQ amqp091-go: Missing Explicit TLS Minimum Version Configuration In URI Parser",
		Description: "While modern versions of the Go compiler toolchain (Go 1.18+) default the implicit minimum version to TLS 1.2... If the library is compiled using legacy Go toolchains (Go < 1.18)...",
		CWE: []string{"CWE-316", "CWE-326"},
	}
	class, src := Classify(v, nil)
	if class != ClassCryptoDowngrade {
		t.Fatalf("expected ClassCryptoDowngrade, got %s (source: %s)", class, src)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestClassify_CryptoDowngrade" ./internal/exploit`
Expected: FAIL (`ClassCryptoDowngrade` undefined or returned `ClassInfoLeak`).

- [ ] **Step 3: Implement `ClassCryptoDowngrade` in `internal/exploit/classify.go`**

1. Define `ClassCryptoDowngrade Class = "CRYPTO_DOWNGRADE"`.
2. In `cweClass`, map:
   - `"326": ClassCryptoDowngrade`
   - `"327": ClassCryptoDowngrade`
   - `"757": ClassCryptoDowngrade`
3. In `Classify`, check: when an advisory has multiple CWEs including CWE-316 and CWE-326/327/757, or when summary/description indicates TLS downgrade, prioritize `ClassCryptoDowngrade` over `ClassInfoLeak`.
4. In `keywordClass`, add regex for TLS min version and protocol downgrade before `ClassInfoLeak`:
   ```go
   {regexp.MustCompile(`(?i)(tls|ssl).*min(imum)?[- ]?version|downgrade.*(tls|ssl|protocol|cipher)|implicit.*toolchain.*(tls|ssl)|minversion.*(toolchain|default)`), ClassCryptoDowngrade},
   ```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v -run "TestClassify_CryptoDowngrade" ./internal/exploit`
Expected: PASS.
Run: `go test ./internal/exploit/...`
Expected: PASS (all existing classification tests pass without regression).

- [ ] **Step 5: Commit**

```bash
git add internal/exploit/classify.go internal/exploit/classify_test.go
git commit -m "feat(exploit): introduce ClassCryptoDowngrade and prioritize over InfoLeak"
```

---

### Task 3: Exploit Pattern & Platform Bound Extraction

**Files:**
- Modify: `internal/exploit/patterns.go:60-156`
- Modify: `internal/exploit/builder.go:150-185`
- Test: `internal/exploit/patterns_test.go`
- Test: `internal/evaluator/platform_test.go`

**Interfaces:**
- Consumes: `ClassCryptoDowngrade`, `domain.ConditionPlatform`
- Produces: `Registry` entry for `ClassCryptoDowngrade` with mandatory `C-PLATFORM` (`go_version: bound`), extraction of `go_version` bound in `builder.go`.

- [ ] **Step 1: Write failing unit tests in `patterns_test.go` and `platform_test.go`**

In `internal/exploit/patterns_test.go`:
```go
func TestPattern_CryptoDowngrade(t *testing.T) {
	v := domain.Vulnerability{
		ID:          "GHSA-33mj-cw25-m34h",
		Summary:     "Missing Explicit TLS Minimum Version Configuration",
		Description: "If compiled with legacy Go toolchains (Go < 1.18)...",
		CWE:         []string{"CWE-326"},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/mod", Symbol: "tlsConfigFromURI"},
		},
	}
	b := Builder{}
	m, lims := b.Build(context.Background(), v, nil, nil)
	if len(lims) > 0 {
		t.Logf("limitations: %v", lims)
	}
	if m.Class != string(ClassCryptoDowngrade) {
		t.Fatalf("expected class %s, got %s", ClassCryptoDowngrade, m.Class)
	}
	var platCond *domain.Condition
	for i := range m.Mandatory {
		if m.Mandatory[i].Kind == domain.ConditionPlatform {
			platCond = &m.Mandatory[i]
			break
		}
	}
	if platCond == nil {
		t.Fatalf("expected mandatory ConditionPlatform in exploit model, got: %+v", m.Mandatory)
	}
	if platCond.Params["go_version"] != "<1.18" {
		t.Fatalf("expected go_version <1.18, got %q", platCond.Params["go_version"])
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v -run "TestPattern_CryptoDowngrade" ./internal/exploit`
Expected: FAIL (no pattern for `ClassCryptoDowngrade`).

- [ ] **Step 3: Implement pattern and bound extraction**

1. In `internal/exploit/patterns.go`, add pattern in `Registry`:
   ```go
   {
       Classes: []Class{ClassCryptoDowngrade},
       Mandatory: []ConditionTmpl{
           {ID: "C-REACH", Role: RoleReach, Kind: domain.ConditionSymbolReachable,
               Description: "product reaches the vulnerable cryptographic/TLS configuration API"},
           {ID: "C-PLATFORM", Kind: domain.ConditionPlatform,
               Description: "runtime toolchain allows insecure protocol negotiation (e.g. legacy TLS floor)",
               Params:      map[string]string{"go_version": "<1.18"}},
       },
       Supporting: []ConditionTmpl{
           {ID: "C-EXPOSURE", Kind: domain.ConditionConfiguration,
               Description: "network exposure of the vulnerable surface",
               Params:      map[string]string{domain.ParamCheck: domain.CheckExposure}},
       },
   },
   ```
2. In `internal/exploit/builder.go`, when building for `ClassCryptoDowngrade`:
   Extract version bound from `v.Description` and `v.Summary` using regex:
   `var toolchainBoundRE = regexp.MustCompile(`(?i)(?:Go|toolchain)[^\w\n]*(?:<|<=|prior to|before)\s*v?(\d+\.\d+(?:\.\d+)?)`)`
   If found, set `cond.Params["go_version"] = "<" + match[1]`.
   If not explicitly found, default to `"<1.18"`.

- [ ] **Step 4: Run unit tests to verify they pass**

Run: `go test -v -run "TestPattern_CryptoDowngrade" ./internal/exploit`
Expected: PASS.
Run: `go test -v -run "TestPlatformEvaluate" ./internal/evaluator`
Expected: PASS.
Run: `go test ./internal/exploit/... ./internal/evaluator/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/exploit/patterns.go internal/exploit/builder.go internal/exploit/patterns_test.go
git commit -m "feat(exploit): add CryptoDowngrade pattern with mandatory toolchain C-PLATFORM condition"
```

---

### Task 4: Live Corpus Validation, Corpus Baseline & Docs Sync (closing B18)

**Files:**
- Modify: `eval/live-corpus.json` (narrow `ghsa-33mj-cw25-m34h` expect to `["NO_EXPLOIT_PATH_FOUND"]`)
- Modify: `eval/ground-truth.md` (mark defect D3 fixed, update table)
- Modify: `docs/dev/gap-analysis.md` (close B18 in §1, remove from §2)
- Modify: `eval/README.md` (document resolution of GHSA-33mj as NO_EXPLOIT_PATH_FOUND)
- Move: `docs/dev/specs/2026-10-04-toolchain-platform-conditions-design.md` -> `docs/dev/history/features/2026-10-04-toolchain-platform-conditions-design.md`
- Remove: `docs/dev/plans/2026-10-04-toolchain-platform-conditions-plan.md`

- [ ] **Step 1: Run single-case evaluation on `ghsa-33mj-cw25-m34h` in live-corpus**

Command:
```bash
VA_PRODUCT_REPO=${VA_PRODUCT_REPO} go run ./cmd/izyan eval --corpus eval/live-corpus.json --case ghsa-33mj-cw25-m34h
```
Expected: PASS, `actual: NO_EXPLOIT_PATH_FOUND`, `status: PASS`, `false_safe: 0`.

- [ ] **Step 2: Run full 38-case evaluation on autonomous corpus**

Command:
```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
```
Expected: 38/38 PASS (18 EXPLOITABLE, 20 CLEARED, 0 INCONCLUSIVE, 0 fail, false_safe = 0).

- [ ] **Step 3: Run standard hygiene checks**

Commands:
```bash
gofmt -l .
go vet ./...
go test ./...
```
Expected: 0 errors, all tests pass.

- [ ] **Step 4: Update documentation and ground truth**

- In `eval/live-corpus.json`: update `ghsa-33mj-cw25-m34h` to `expect: ["NO_EXPLOIT_PATH_FOUND"]`.
- In `eval/ground-truth.md`: mark defect D3 as fixed (`D3 (P2, исправлен): классификатор 33mj определяет ClassCryptoDowngrade; C-PLATFORM по go_version опровергается на Go >= 1.18 -> NO_EXPLOIT_PATH_FOUND`).
- In `docs/dev/gap-analysis.md`: delete B18 row from §2, add closing row in §1.
- In `eval/README.md`: update live corpus status.
- Archive design spec to `docs/dev/history/features/` and remove temporary implementation plan.

- [ ] **Step 5: Commit**

```bash
git commit -m "docs: close B18 and mark GHSA-33mj resolved as NO_EXPLOIT_PATH_FOUND"
```
