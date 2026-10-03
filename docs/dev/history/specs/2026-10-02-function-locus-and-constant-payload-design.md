# Design: Function-Level Locus Unreachability and Constant Parser Payload

## 1. Overview and Motivation

In the current baseline evaluation (`eval/README.md` and `eval/corpus-real.json`), several cases terminate in `INCONCLUSIVE` against `govulncheck`'s `reachable` reports:
1. `real-micro-pkg-6443` (advisory `GO-2026-6443`): The defect locus is `google.golang.org/grpc/internal/xds/server.RouteAndProcess`. The product imports `google.golang.org/grpc/xds` for bootstrap/client types, which links the `internal/xds/server` package into the build graph. The current analyzer only checks for total package absence (`locus-package-absent`). When the package is linked but the function is uncalled, it stops at `INCONCLUSIVE`.
2. `real-yaml-const`, `real-yaml3-const`, `real-protojson-const` (advisories `GO-2021-0061`, `GO-2022-0603`, `GO-2024-2611`): The product passes compile-time constants (e.g. `[]byte(baseline)`) to `yaml.Unmarshal` or `protojson.Unmarshal`. The provenance engine resolves the input bytes to `CONSTANT`, but because the parser internally uses `reflect` to decode into the target struct `out`, `ingress.go` flags reflective operations in the decoding cone as untrusted/unresolved, demoting the claim to `INCONCLUSIVE`.

In ground truth, all four cases are completely unexploitable (`NO_EXPLOIT_PATH_FOUND`). This design adds deterministic falsifiers and negative verifications to prove safety in both scenarios without violating the `false-safe=0` invariant.

---

## 2. Architecture & Components

### 2.1 Function-Level Locus Unreachability (`FalsifierLocusFunctionUnreached`)

#### Domain Types:
- Add `domain.FalsifierLocusFunctionUnreached domain.FalsifierKind = "locus-function-unreached"` to `internal/domain/domain.go`.

#### Evaluator (`internal/evaluator/locus.go`):
- In `evalLocus`:
  - When `len(present) > 0` (locus packages are present in the build graph):
    - Check if any symbol in $L$ is present in `c.EvidenceGraph.CallPaths` (govulncheck call traces).
    - Check if any symbol in $L$ is present in `c.EvidenceGraph.ModuleReachable`.
    - If any symbol in $L$ has a call path or module chain, `evalLocus` returns `ClaimTrue`.
    - If NO symbols in $L$ have any observed call path or module chain:
      - Emit a candidate `ClaimFalse` with `claim.Falsifier = domain.FalsifierLocusFunctionUnreached`.
      - Record the limitation: `FALSE is a candidate: function unreachability requires negative verification of callers and dynamic markers`.

#### Negative Verification (`internal/goanalysis/locusverify.go` and `internal/goanalysis/negative.go`):
- In `Verifier.VerifyFalse`:
  - When `claim.Falsifier == domain.FalsifierLocusFunctionUnreached`:
    - Dispatch to `v.verifyLocusFunctionUnreached(c, claim, cond)`.
  - In `verifyLocusFunctionUnreached`:
    - For each subject symbol in $L$:
      1. Check static call sites in product and dependency source using the existing AST index (`Index.CheckSubjectReachable` or symbol reference table).
      2. If the symbol is in an `internal/` package of a dependency (like `google.golang.org/grpc/internal/xds/server`), external packages cannot import or reference it directly by Go compiler rules.
      3. Verify that no entrypoint in product code reaches any caller in the dependency that calls this symbol.
      4. Verify dynamic markers: check if any interface method or reflection invocation matches the symbol.
    - If no call path exists and dynamic markers are clean, set `nv.Status = domain.NegativeVerified`.
    - If a call path or uncontained dynamic escape is found, demote to `domain.NegativeContradicted` (or `NegativeInsufficientScope`) -> claim remains `UNKNOWN`.

---

### 2.2 Constant Payload on Parsers with Output Reflection

#### Ingress Provenance Analysis (`internal/goanalysis/ingress.go` and `internal/goanalysis/provenance.go`):
- In parser unmarshaling calls (such as `yaml.Unmarshal(in, out)` or `protojson.Unmarshal(in, out)`):
  - Sink input argument index is 0 (`in`).
  - Sink output target index is 1 (`out`).
- Currently, when `ingressScan` walks the call tree of `yaml.Unmarshal`:
  - It encounters `reflect.ValueOf` and other reflective value operations inside `yaml.Unmarshal`.
  - `ingress.go:1275` registers:
    `s.addUnknownCall(pkg, d, call, fn, "reflective value operation may carry or write non-constant data")`
- **Design Rule**:
  - Distinguish between **source input data streams** and **destination reflection buffers**.
  - When the sink argument being evaluated for `C-PEER-INPUT` / `C-UNTRUSTED-INPUT` is the payload parameter (`in`), and its provenance in the product call site is proved to be `CONSTANT` (e.g. string literal, const slice), internal reflection on the destination struct parameter (`out`) inside the unmarshaler must NOT invalidate the constant provenance of `in`.
  - Reflection on `out` only mutates the destination struct fields; it does NOT synthesize or alter the input bytes passed into `in`.
  - Therefore, `reflect.ValueOf` calls on the destination parameter or internal struct traversal do not add an `UnknownCall` blocker to the ingress cone of the payload argument.

#### Evaluator (`internal/evaluator/input.go`):
- When evaluating `C-PEER-INPUT` or `C-UNTRUSTED-INPUT`:
  - If all data flows to the payload sink resolve to `OriginConstant`, emit candidate `ClaimFalse` with `FalsifierConstantPayload` (or existing `FalsifierConstantSinkArg`).
  - Negative verification confirms that no dynamic markers or concurrent writes mutate the constant payload bytes.
  - The condition evaluates to `ClaimFalse` (`VERIFIED`) -> mandatory input condition fails -> `NO_EXPLOIT_PATH_FOUND`.

---

## 3. Testing & Verification

1. **Unit Tests**:
   - `internal/evaluator/locus_test.go`: Test that `evalLocus` emits candidate `FalsifierLocusFunctionUnreached` when locus package is present but symbols have no call traces.
   - `internal/goanalysis/locusverify_test.go`: Test that `verifyLocusFunctionUnreached` verifies unreachability for internal package functions unreferenced by product code.
   - `internal/goanalysis/ingress_test.go`: Test that constant payload passed to `yaml.Unmarshal` or `protojson.Unmarshal` is not invalidated by internal decoding reflection.

2. **Corpus Verification**:
   - Run `real-micro-pkg-6443` -> must output `NO_EXPLOIT_PATH_FOUND` (`cleared: ДА`).
   - Run `real-yaml-const`, `real-yaml3-const`, `real-protojson-const` -> must output `NO_EXPLOIT_PATH_FOUND` (`cleared: ДА`).
   - Run full 38-case real corpus -> cleared rate increases to 19/38, with `false-safe = 0`.
   - Run standard regression suite: `gofmt`, `go vet ./...`, `go test ./...`.
