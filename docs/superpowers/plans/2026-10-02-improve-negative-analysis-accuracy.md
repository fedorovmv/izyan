# Improve Negative Analysis Accuracy & Reduce False Inconclusive Plan

## Goal
Eliminate unnecessary `INCONCLUSIVE` verdicts on non-vulnerable code by:
1. Fixing `govulncheck` trace parsing so module/package-level findings without function call paths are not misreported as call paths / Reachable.
2. Scoping dynamic-marker (`reflect`) demotion so bare `reflect` imports in product code (e.g. JSON/logging) do not falsely invalidate static reachability falsifiers on standalone functions.
3. Adding a "Client vs Server" architectural role falsifier (`FalsifierClientOnlyUsage`) to decisively dismiss server vulnerabilities in client-only code.
4. Adding deployment trust boundary evaluation (`--trusted-broker` / `--trusted-infrastructure`) to resolve peer/config precondition conditions.
5. Scoping `ModuleInternalReach` opaque dispatch to the call tree of used APIs.
6. Re-running all real-world evaluation cases and updating the comparison table.

## User Review Required
> [!IMPORTANT]
> Zero internal corporate paths, usernames, repo names, or ticket IDs in git-tracked code, commits, or documentation.

---

### Task 1: Fix `govulncheck` Trace/CallPath Parsing & Reachability Status (TDD)
- **Files**:
  - `internal/goanalysis/govulncheck.go`
  - `internal/goanalysis/govulncheck_test.go`
  - `internal/states/states.go`
  - `internal/report/report.go`
  - `internal/report/report_test.go`
- **Changes**:
  - In `internal/goanalysis/govulncheck.go`:
    - Add `(f Finding) HasCallPath() bool`: returns `true` only if `len(f.Trace) > 0` and at least one frame has non-empty `Function`.
    - In `(f Finding) CallPath()`: skip frames with empty `Function` or return empty `domain.CallPath{}` if `!f.HasCallPath()`.
  - In `internal/states/states.go`:
    - In `CollectEvidence.RunGovulncheck`: only add `f.CallPath()` to `c.EvidenceGraph.CallPaths` when `f.HasCallPath()`.
  - In `internal/report/report.go`:
    - Ensure `govulncheckSummary` correctly distinguishes:
      - Real call paths: `Обнаружены пути вызова к уязвимому коду (N)`
      - Package/module only in deps, zero calls: `Трасса вызовов от кода продукта не обнаружена (пакет импортирован, функции не вызываются)`
- **Verification**: `go test ./internal/goanalysis/... ./internal/states/... ./internal/report/...`

---

### Task 2: Scope Reflect Dynamic-Marker Demotion to Targeted Usages (TDD)
- **Files**:
  - `internal/goanalysis/negative.go`
  - `internal/goanalysis/negative_test.go`
  - `internal/review/review.go`
  - `internal/review/review_test.go`
- **Changes**:
  - In `internal/goanalysis/negative.go`:
    - Analyze `m.Kind == "reflect"`: in Go, standalone functions (functions without receiver) cannot be invoked dynamically via `reflect` by name. Only methods on values can be invoked via `MethodByName`.
    - When validating `FalsifierGovulncheckSilence`, `FalsifierNoProductReader`, or `FalsifierMissingPairMember`:
      - If all subjects are package-level standalone functions (no receiver), bare `reflect` import in the product does not widen the call graph to those functions.
      - Do not emit `reflect usage in product widens the call graph` limitation for standalone function subjects.
  - In `internal/review/review.go`:
    - Demotion from high-severity dynamic dispatch limitation should only occur if the limitation actually applies to the claim's subjects.
- **Verification**: `go test ./internal/goanalysis/... ./internal/review/...`

---

### Task 3: Client vs Server Architectural Role Falsifier (TDD)
- **Files**:
  - `internal/domain/domain.go`
  - `internal/evaluator/presence.go` or new `internal/evaluator/role.go`
  - `internal/evaluator/role_test.go`
  - `cmd/analyzer/main.go`
- **Changes**:
  - Define `FalsifierClientOnlyUsage = "client-only-usage"`.
  - Add `ClientRoleEvaluator`:
    - When a vulnerability's root cause or condition requires a server endpoint / server listener / server handshake (e.g. `ssh.NewServerConn`, `grpc.NewServer`), but AST evidence shows the product only invokes client APIs (e.g. `ssh.Dial`, `grpc.Dial`) and no server constructors/listeners are reachable in product code:
    - Yield `ClaimFalse` with `FalsifierClientOnlyUsage`.
    - Negative verification verifies absence of server entrypoints.
- **Verification**: `go test ./internal/evaluator/...`

---

### Task 4: Trust Boundary & Deployment Infrastructure Context (TDD)
- **Files**:
  - `internal/domain/domain.go`
  - `internal/evaluator/conditions.go`
  - `internal/evaluator/conditions_test.go`
  - `cmd/analyzer/main.go`
- **Changes**:
  - Add flag `--trust-broker` / `--trusted-infrastructure` to `cmd/analyzer/main.go` and `domain.ProductSnapshot` / `domain.AnalysisCase`.
  - When evaluating `ATTACKER_CONTROL` with `input_source == "peer"` or broker inputs (like `C-PEER-INPUT` in `GO-2026-6372`):
    - If `--trusted-broker` is enabled, evaluate `ClaimFalse` with `FalsifierTrustedInfrastructure`.
    - Explanation: "broker infrastructure is designated as trusted in deployment profile; peer-controlled exploit input is prevented".
- **Verification**: `go test ./internal/evaluator/... ./cmd/analyzer/...`

---

### Task 5: Scoped Opaque Dispatch in ModuleInternalReach (TDD)
- **Files**:
  - `internal/goanalysis/source.go`
  - `internal/evaluator/conditions.go`
  - `internal/evaluator/conditions_test.go`
- **Changes**:
  - When computing `ModuleInternalReach`, record which exported APIs have opaque dispatch.
  - If the product uses API A (which has clean static dispatch), opaque dispatch in unrelated API B inside the same library should not prevent falsifying reachability of API B's sinks.
- **Verification**: `go test ./internal/evaluator/...`

---

### Task 6: Re-run Real Eval Cases & Update Comparison Table
- Re-run `GO-2026-5841`, `GO-2026-6303`, `GO-2026-4950`, `GO-2026-6372`, `GO-2026-6443`, `GO-2026-6441`, `GO-2026-5942`, `GO-2026-5932`, `GO-2026-5024`, `GO-2025-4188`.
- Verify the verdicts and rationale.
- Update `.vuln-analyzer/real-eval/COMPARISON_TABLE.md`.
- Run `gofmt`, `go vet ./...`, `go test ./...`.
