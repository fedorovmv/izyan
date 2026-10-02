# Function-Level Locus Unreachability and Constant Parser Payload Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement function-level unreachability for defect loci in linked packages (`real-micro-pkg-6443`) and constant payload protection against parser output reflection (`real-yaml-const`, `real-yaml3-const`, `real-protojson-const`), turning 4 `INCONCLUSIVE` cases into proven `NO_EXPLOIT_PATH_FOUND` verdicts with `false-safe=0`.

**Architecture:** 
1. In `internal/domain`, add `FalsifierLocusFunctionUnreached`.
2. In `internal/evaluator/locus.go`, detect when locus packages are linked but locus symbols $L$ have zero call traces or module chains, proposing candidate `ClaimFalse`.
3. In `internal/goanalysis/locusverify.go`, implement `verifyLocusFunctionUnreached` to statically verify zero product call sites, dependency encapsulation (`internal/` packages), and absence of dynamic dispatch escapes.
4. In `internal/goanalysis/ingress.go`, isolate the input payload argument (`in`) from destination struct reflection (`out`) during unmarshaling, preserving `OriginConstant`.
5. Update `eval/corpus-real.json`, verify on the 38-case real corpus, and synchronize documentation (`eval/README.md`, `docs/dev/current/gap-analysis.md`).

**Tech Stack:** Go 1.26, `go/ast`, `go/types`, `golang.org/x/tools/go/packages`.

## Global Constraints
- Zero internal corporate paths, names, or credentials in tracked files or tests.
- Safety invariant: safe negative verdicts require a verified falsifier on a mandatory condition (`false-safe=0`).
- All code must pass `gofmt`, `go vet ./...`, and `go test ./...`.

---

### Task 1: Domain Type and Evaluator Candidate for Function-Level Locus Unreachability

**Files:**
- Modify: `internal/domain/domain.go`
- Modify: `internal/evaluator/locus.go`
- Test: `internal/evaluator/locus_test.go`

**Interfaces:**
- Produces: `domain.FalsifierLocusFunctionUnreached = "locus-function-unreached"`
- Produces: `evalLocus` returns `ClaimFalse` with `FalsifierLocusFunctionUnreached` when locus packages are linked but symbols in $L$ have no call traces or module chains.

- [ ] **Step 1: Write failing test in `internal/evaluator/locus_test.go`**

```go
func TestEvalLocusFunctionUnreachedCandidate(t *testing.T) {
	cond := domain.Condition{
		ID:       "C-LOCUS",
		Subjects: []domain.SymbolRef{{Package: "example.com/dep/internal/pkg", Symbol: "VulnerableFunc"}},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				{
					ID:      "EV-PACKAGE-LIST",
					Kind:    domain.EvidencePackageList,
					Content: `[{"ImportPath":"example.com/dep/internal/pkg"}]`,
				},
			},
		},
	}
	claim := evalLocus(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("expected candidate ClaimFalse, got %v", claim.Result)
	}
	if claim.Falsifier != domain.FalsifierLocusFunctionUnreached {
		t.Fatalf("expected falsifier %s, got %s", domain.FalsifierLocusFunctionUnreached, claim.Falsifier)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/evaluator -run TestEvalLocusFunctionUnreachedCandidate`
Expected: FAIL (undefined constant or returns ClaimUnknown)

- [ ] **Step 3: Implement minimal code**

In `internal/domain/domain.go`:
```go
const (
	...
	FalsifierLocusFunctionUnreached FalsifierKind = "locus-function-unreached"
)
```

In `internal/evaluator/locus.go`:
When `len(present) > 0`:
Check if any symbol in `symbols` has a call path in `c.EvidenceGraph.CallPaths` or is in `c.EvidenceGraph.ModuleReachable`.
If neither, instead of returning `ClaimUnknown`, set:
```go
claim.Result = domain.ClaimFalse
claim.Falsifier = domain.FalsifierLocusFunctionUnreached
claim.EvidenceIDs = ids
claim.Explanation = fmt.Sprintf("пакеты с уязвимым кодом входят в сборку, но функции дефектного локуса (%d) не имеют обнаруженных трасс вызовов; требуется верификация недостижимости", len(symbols))
claim.Limitations = append(claim.Limitations, "FALSE (предварительно): недостижимость функции в скомпилированном пакете требует негативной верификации")
return claim
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./internal/evaluator -run TestEvalLocusFunctionUnreachedCandidate`
Expected: PASS

- [ ] **Step 5: Run all evaluator tests and commit**

Run: `go test ./internal/evaluator/...`
Run: `git commit -am "feat(evaluator): emit candidate ClaimFalse for locus function unreachability"`

---

### Task 2: Negative Verification for `locus-function-unreached`

**Files:**
- Modify: `internal/goanalysis/negative.go`
- Modify: `internal/goanalysis/locusverify.go`
- Test: `internal/goanalysis/locusverify_test.go`

**Interfaces:**
- Consumes: `domain.FalsifierLocusFunctionUnreached`
- Produces: `Verifier.verifyLocusFunctionUnreached(c, claim, cond) domain.Claim`

- [ ] **Step 1: Write failing test in `internal/goanalysis/locusverify_test.go`**

```go
func TestVerifyLocusFunctionUnreached(t *testing.T) {
	// Test that an internal unreferenced function in a linked package is verified as NegativeVerified
	ix := &Index{
		Dir: t.TempDir(),
	}
	v := Verifier{Source: ix}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc/internal/xds/server", Symbol: "RouteAndProcess"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified, got %+v", verified.NegativeVerification)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/goanalysis -run TestVerifyLocusFunctionUnreached`
Expected: FAIL

- [ ] **Step 3: Implement `verifyLocusFunctionUnreached` in `internal/goanalysis/locusverify.go`**

In `internal/goanalysis/negative.go`:
```go
	if claim.Falsifier == domain.FalsifierLocusFunctionUnreached {
		return v.verifyLocusFunctionUnreached(c, claim, cond)
	}
```

In `internal/goanalysis/locusverify.go`:
Implement `verifyLocusFunctionUnreached`:
1. Check that no call paths or module reachability chains exist to any subject symbol.
2. For symbols in `internal/` packages: verify product code does not import the `internal/` package directly (compiler restriction guarantees no direct external references).
3. If source index is available, verify that reachable entry points do not invoke the subject symbol.
4. If verified, set `nv.Status = domain.NegativeVerified`.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./internal/goanalysis -run TestVerifyLocusFunctionUnreached`
Expected: PASS

- [ ] **Step 5: Run all goanalysis tests and commit**

Run: `go test ./internal/goanalysis/...`
Run: `git commit -am "feat(goanalysis): implement negative verification for locus-function-unreached"`

---

### Task 3: Isolate Constant Ingress Payload from Target Struct Reflection in Parsers

**Files:**
- Modify: `internal/goanalysis/ingress.go`
- Test: `internal/goanalysis/ingress_test.go`

**Interfaces:**
- Produces: `ingressScan` does not add `UnknownCall` blocker for internal `reflect` operations when the parsed payload input argument is `OriginConstant`.

- [ ] **Step 1: Write failing test in `internal/goanalysis/ingress_test.go`**

```go
func TestConstantPayloadNotInvalidatedByDecoderReflection(t *testing.T) {
	// Verify that a constant byte slice passed to a parser whose body uses reflect
	// maintains constant origin without being demoted by destination struct reflection.
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test -v ./internal/goanalysis -run TestConstantPayloadNotInvalidatedByDecoderReflection`
Expected: FAIL

- [ ] **Step 3: Implement reflection isolation in `internal/goanalysis/ingress.go`**

In `internal/goanalysis/ingress.go:1275`:
When encountering `reflect` calls inside unmarshaling functions (`yaml.Unmarshal`, `protojson.Unmarshal`), check if the reflection is operating on the target output object or if the input payload argument is an immutable constant. Do not add an unresolvable blocker to the input payload cone for destination unmarshaling reflection.

- [ ] **Step 4: Run test to verify it passes**

Run: `go test -v ./internal/goanalysis -run TestConstantPayloadNotInvalidatedByDecoderReflection`
Expected: PASS

- [ ] **Step 5: Run all goanalysis tests and commit**

Run: `go test ./internal/goanalysis/...`
Run: `git commit -am "feat(ingress): isolate constant payload input from parser destination reflection"`

---

### Task 4: Corpus Validation, Documentation & Baseline Sync

**Files:**
- Modify: `eval/corpus-real.json` (update expect for `real-micro-pkg-6443`, `real-yaml-const`, `real-yaml3-const`, `real-protojson-const` to include `NO_EXPLOIT_PATH_FOUND`)
- Modify: `eval/README.md` (update baseline table and cleared count from 15/38 to 19/38)
- Modify: `docs/dev/current/gap-analysis.md`

- [ ] **Step 1: Update expectations in `eval/corpus-real.json`**
Add `NO_EXPLOIT_PATH_FOUND` to `expect` arrays for the 4 cases.

- [ ] **Step 2: Run corpus evaluation on the 4 targeted cases**
Run: `go test ./cmd/analyzer -run TestCorpusRealCases` or evaluate via `analyzer eval`.
Verify all 4 cases evaluate to `NO_EXPLOIT_PATH_FOUND`.

- [ ] **Step 3: Run full live corpus regression**
Verify: `false-safe = 0`, cleared rate increases to 19/38.

- [ ] **Step 4: Update `eval/README.md` and `docs/dev/current/gap-analysis.md`**
Reflect new cleared cases and updated metrics.

- [ ] **Step 5: Run full project verification**
```bash
gofmt
go vet ./...
go test ./...
```

- [ ] **Step 6: Commit**
`git commit -am "docs(eval): update baseline table for 19/38 cleared cases with function-locus and constant payload proofs"`
