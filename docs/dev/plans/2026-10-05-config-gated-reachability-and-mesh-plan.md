# B6: Config-Gated Reachability & Mesh Ingress Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement configuration-bound network listener resolution, Istio/Kubernetes mesh perimeter detection, and dead code elimination under disabled feature flags with safe negative verification.

**Architecture:** Extend `internal/goanalysis/exposure.go` to resolve struct fields and package vars to concrete bind addresses; enhance `internal/exposure/deploy.go` to distinguish public Gateway ingress from cluster-internal mesh services and detect `AuthorizationPolicy`; update `internal/evaluator/reachable.go` and `exposure.go` to falsify `C-REACH` (`FalsifierConfigGatedOff`) when calls are dead code under disabled config knobs and falsify `C-EXPOSURE` (`FalsifierLoopbackOnly`) when public scope is required on internal-only binds.

**Tech Stack:** Go, `go/ast`, `go/types`, `golang.org/x/tools/go/packages`.

## Global Constraints

- Generality rule: NO case-specific identifiers, package paths, or product names in `internal/goanalysis/` or `internal/evaluator/` (`docs/agent-rules/generality.md`).
- Safety invariant: safe negative verdicts require a verified falsifier on a mandatory condition (`false-safe = 0`).
- Testing rule: run ONLY fast targeted unit tests during tasks; full corpus eval is reserved strictly for Task 4.
- Git rule: commits are strictly local; zero intermediate `git push`.
- Privacy rule: zero internal corporate paths or credentials.

---

### Task 1: Domain Constants & Config Resolution for Exposure Listeners

**Files:**
- Modify: `internal/domain/domain.go:495-505`
- Modify: `internal/goanalysis/exposure.go:370-420`
- Test: `internal/goanalysis/exposure_test.go`

**Interfaces:**
- Produces: `domain.FalsifierConfigGatedOff = "config-feature-disabled"`, `domain.FalsifierLoopbackOnly = "loopback-only"`.
- Modifies: `(ix *Index) exprStringValue(info *types.Info, pkg *packages.Package, fn *ast.FuncDecl, e ast.Expr) (string, string)` to resolve struct selector fields and package vars to concrete string values.

- [ ] **Step 1: Add falsifier constants in `internal/domain/domain.go`**

```go
const (
	FalsifierConfigGatedOff = "config-feature-disabled"
	FalsifierLoopbackOnly   = "loopback-only"
)
```

- [ ] **Step 2: Write failing unit tests in `internal/goanalysis/exposure_test.go`**

Test resolving `net.Listen("tcp", cfg.Addr)` where `cfg := Config{Addr: "127.0.0.1:8080"}` and package var `var defaultPort = "127.0.0.1:9090"`.

- [ ] **Step 3: Run test to verify it fails (RED)**

Run: `go test -v -run TestExposure_ConfigFieldAndPackageVar ./internal/goanalysis`
Expected: FAIL (empty address or unknown scope).

- [ ] **Step 4: Implement field and package var resolution in `internal/goanalysis/exposure.go`**

Enhance `exprString` to look up struct field assignments via `ix.FieldAssignments` or package ASTs when encountering `*ast.SelectorExpr` or `*types.Var`.

- [ ] **Step 5: Run test to verify it passes (GREEN)**

Run: `go test -v -run TestExposure_ConfigFieldAndPackageVar ./internal/goanalysis`
Expected: PASS.

- [ ] **Step 6: Commit Task 1**

```bash
git add internal/domain/domain.go internal/goanalysis/exposure.go internal/goanalysis/exposure_test.go
git commit -m "feat(goanalysis): resolve listener addresses from config fields and package vars"
```

---

### Task 2: Service Mesh & Istio Manifest Perimeter Scan

**Files:**
- Modify: `internal/exposure/deploy.go:120-180`
- Modify: `internal/evaluator/exposure.go:30-80`
- Test: `internal/exposure/deploy_test.go`
- Test: `internal/evaluator/exposure_test.go`

**Interfaces:**
- Produces: `deployFact` distinguishing `ScopeLoopback` / cluster-internal mesh services from `ScopeAllInterfaces` public Gateways/LoadBalancers.
- Modifies: `evaluator.Exposure.Evaluate` to falsify `C-EXPOSURE` when `cond.Params["scope"] == "public"` and all listeners are loopback/mesh-internal.

- [ ] **Step 1: Write failing unit tests in `internal/exposure/deploy_test.go` and `internal/evaluator/exposure_test.go`**

1. In `deploy_test.go`: test that a Kubernetes manifest with only `Service: ClusterIP` (no Gateway/Ingress) produces cluster-internal/loopback scope, whereas `Gateway` / `VirtualService` produces `ScopeAllInterfaces`.
2. In `deploy_test.go`: test that `kind: AuthorizationPolicy` or `kind: RequestAuthentication` produces `inbound` `auth-middleware`.
3. In `exposure_test.go`: test that when `cond.Params["scope"] == "public"` and only loopback/cluster-internal exposure facts exist, `claim.Result == domain.ClaimFalse` with `claim.Falsifier == domain.FalsifierLoopbackOnly`.

- [ ] **Step 2: Run test to verify it fails (RED)**

Run: `go test -v -run "TestDeployIstio|TestExposure_PublicScopeFalsified" ./internal/exposure ./internal/evaluator`
Expected: FAIL.

- [ ] **Step 3: Implement Istio/k8s manifest scan and scope-guarded exposure evaluation**

1. In `internal/exposure/deploy.go`:
   - Detect `AuthorizationPolicy` and `RequestAuthentication` as `inbound` `auth-middleware`.
   - Mark `Service: ClusterIP` without ingress as `domain.ScopeLoopback` (cluster-internal).
2. In `internal/evaluator/exposure.go`:
   - Check if `cond.Params[domain.ParamScope] == "public"`: if `inboundLocal && !inboundPublic`, return `claim.Result = domain.ClaimFalse`, `claim.Falsifier = domain.FalsifierLoopbackOnly`.

- [ ] **Step 4: Run test to verify it passes (GREEN)**

Run: `go test -v -run "TestDeployIstio|TestExposure_PublicScopeFalsified" ./internal/exposure ./internal/evaluator`
Expected: PASS.

- [ ] **Step 5: Commit Task 2**

```bash
git add internal/exposure/ internal/evaluator/
git commit -m "feat(exposure): detect istio mesh perimeter and support public scope falsification"
```

---

### Task 3: Feature Flag Guard Analysis & Dead Code Elimination in Reachability

**Files:**
- Modify: `internal/goanalysis/config.go:170-240`
- Modify: `internal/evaluator/reachable.go:30-100`
- Test: `internal/goanalysis/config_test.go`
- Test: `internal/evaluator/reachable_test.go`

**Interfaces:**
- Modifies: `(ix *Index) ConfigGated(ctx context.Context, site domain.CallSite)` or `(ix *Index) IsCallSiteDeadCode(ctx context.Context, site domain.CallSite) (bool, string, error)`.
- Modifies: `evaluator.SymbolReachable.Evaluate` to evaluate `claim.Result = domain.ClaimFalse` with `FalsifierConfigGatedOff` when all call paths pass through statically disabled feature gates.

- [ ] **Step 1: Write failing unit tests in `internal/evaluator/reachable_test.go` and `internal/goanalysis/config_test.go`**

1. Test where vulnerable function `vuln()` is called only inside `if cfg.EnableFeature { vuln() }`, and `cfg.EnableFeature` is statically `false` or never set `true` for a bool field.
2. Verify `C-REACH` evaluates to `ClaimFalse` with `claim.Falsifier == domain.FalsifierConfigGatedOff`.
3. Test where `cfg.EnableFeature` is dynamic (`os.Getenv`): verify `C-REACH` evaluates to `ClaimTrue` with `conditional-reachability` limitation.

- [ ] **Step 2: Run test to verify it fails (RED)**

Run: `go test -v -run "TestReachable_ConfigGatedDeadCode" ./internal/evaluator`
Expected: FAIL.

- [ ] **Step 3: Implement dead-code guard detection and evaluation in `internal/goanalysis/config.go` and `internal/evaluator/reachable.go`**

Connect `ix.FieldAssignments` and `ix.SymbolFieldType` to determine if the guarding flag is statically false.
If all call sites for the subject are gated by a statically false condition, emit `ClaimFalse` with `FalsifierConfigGatedOff`.

- [ ] **Step 4: Run test to verify it passes (GREEN)**

Run: `go test -v -run "TestReachable_ConfigGatedDeadCode" ./internal/evaluator`
Expected: PASS.

- [ ] **Step 5: Commit Task 3**

```bash
git add internal/goanalysis/ internal/evaluator/
git commit -m "feat(evaluator): eliminate dead code under disabled config flags in reachability"
```

---

### Task 4: Corpus Validation, Baseline & Docs Sync (closing B6)

**Files:**
- Modify: `docs/dev/gap-analysis.md`
- Modify: `eval/README.md`
- Move: `docs/dev/specs/2026-10-05-config-gated-reachability-and-mesh-design.md` -> `docs/dev/history/features/`
- Delete: `docs/dev/plans/2026-10-05-config-gated-reachability-and-mesh-plan.md`

- [ ] **Step 1: Run fast targeted tests across modified packages**

Run: `go test -v ./internal/goanalysis ./internal/exposure ./internal/evaluator ./internal/risk ./internal/report`
Expected: PASS.

- [ ] **Step 2: Run full autonomous corpus evaluation**

Run: `go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4`
Expected: 38/38 cases pass, 0 fail, false-safe = 0.

- [ ] **Step 3: Run repository hygiene checks**

Run: `gofmt -l .`
Run: `go vet ./...`
Run: `go test ./...`

- [ ] **Step 4: Sync documentation**

1. In `docs/dev/gap-analysis.md`:
   - Delete row B6 from §2 table.
   - Add closing row for B6 in §1 table.
2. In `eval/README.md`:
   - Document Config-Gated Reachability and Mesh Ingress.
3. Move design spec to `docs/dev/history/features/`.
4. Remove temporary plan file.

- [ ] **Step 5: Commit Task 4**

```bash
git commit -am "docs: close B6 and document config-gated reachability and mesh ingress"
```
