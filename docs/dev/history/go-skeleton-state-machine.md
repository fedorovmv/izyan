# Go-каркас и state machine

## 1. Domain identifiers

```go
type CaseID string
type EvidenceID string
type ConditionID string
type ClaimID string
type HypothesisID string
type ReviewID string
```

## 2. Workflow states

```text
CREATED
 -> SNAPSHOT_PRODUCT
 -> RESOLVE_VULNERABILITY
 -> CHECK_AFFECTED
 -> RESOLVE_ROOT_CAUSE
 -> BUILD_EXPLOIT_MODEL
 -> COLLECT_EVIDENCE
 -> EVALUATE_CONDITIONS
 -> NEGATIVE_CHECK
 -> REVIEW
 -> REPAIR_ANALYSIS
 -> EVALUATE_VERDICT
 -> BUILD_REPORT
 -> COMPLETED
```

Терминальные альтернативы: `INCONCLUSIVE`, `FAILED`.

`INCONCLUSIVE` — корректный аналитический результат при недостатке доказательств. `FAILED` — инфраструктурная невозможность продолжить.

## 3. AnalysisCase

```go
type AnalysisCase struct {
    ID            CaseID
    Vulnerability Vulnerability
    Product       ProductSnapshot
    Affected      *AffectedResult
    RootCause     *RootCauseModel
    Exploit       *ExploitModel
    EvidenceGraph EvidenceGraph
    Claims        []Claim
    Reviews       []Review
    Verdict       *VerdictResult
    Workflow      WorkflowStatus
}
```

## 4. Core interfaces

### Repository

```go
type Repository interface {
    Snapshot(ctx context.Context, path string, opts SnapshotOptions) (ProductSnapshot, error)
    ReadFile(ctx context.Context, snapshot ProductSnapshot, path string) ([]byte, error)
}
```

### Vulnerability source

```go
type VulnerabilitySource interface {
    Get(ctx context.Context, id string) (*Vulnerability, error)
}
```

### Affected resolver

```go
type AffectedResolver interface {
    Resolve(ctx context.Context, vuln Vulnerability, product ProductSnapshot) (AffectedResult, error)
}
```

### Root cause

```go
type FixResolver interface {
    Resolve(ctx context.Context, vuln Vulnerability) ([]FixReference, error)
}

type RootCauseResolver interface {
    Resolve(ctx context.Context, input RootCauseInput) (RootCauseModel, error)
}

type RootCauseVerifier interface {
    Verify(ctx context.Context, vuln Vulnerability, candidate RootCause, evidence EvidenceGraph) (RootCauseVerification, error)
}
```

### Exploit model

```go
type ExploitModelBuilder interface {
    Build(ctx context.Context, input ExploitModelInput) (ExploitModel, error)
}
```

### Go analysis

```go
type GovulncheckAnalyzer interface {
    Analyze(ctx context.Context, product ProductSnapshot) (GovulncheckResult, error)
}

type SourceAnalyzer interface {
    FindSymbol(...)
    FindCallers(...)
    ReadFunction(...)
    FindEntrypoints(...)
}

type ArgumentTracer interface {
    Trace(ctx context.Context, product ProductSnapshot, callSite CallSite, argIndex int) (DataFlow, error)
}

type ValidationAnalyzer interface {
    FindValidations(ctx context.Context, product ProductSnapshot, flow DataFlow, sink CallSite) ([]Validation, error)
}
```

### Tool layer

```go
type Tool interface {
    Name() string
    Schema() Schema
    Execute(ctx context.Context, req Request) (Result, error)
}

type Request struct {
    CaseID       CaseID
    ConditionID  ConditionID
    HypothesisID HypothesisID
    Purpose      string
    Arguments    json.RawMessage
}
```

### Condition evaluation

```go
type ConditionEvaluator interface {
    Evaluate(ctx context.Context, condition Condition, graph EvidenceGraph) (Claim, error)
}
```

Простые conditions идут через deterministic evaluator, семантические — через semantic evaluator.

### Verdict evaluator

```go
type VerdictEvaluator interface {
    Evaluate(affected AffectedResult, model ExploitModel, claims []Claim) VerdictResult
}
```

Verdict evaluator — чистая функция без LLM, FS, DB или network.

## 5. Verdict logic

```text
VersionAffected == FALSE
 -> NOT_AFFECTED

all mandatory == TRUE
 -> EXPLOITABLE

mandatory == FALSE
AND negative verification == VERIFIED
 -> NO_EXPLOIT_PATH_FOUND

otherwise
 -> INCONCLUSIVE
```

## 6. Reviewer contract

```go
type Reviewer interface {
    Review(ctx context.Context, input ReviewInput) (Review, error)
}
```

Reviewer возвращает только `ACCEPT` или `REVISE`; не заменяет Verdict Engine.

## 7. StateHandler

```go
type StateHandler interface {
    State() WorkflowState
    Run(ctx context.Context, c *AnalysisCase) (Transition, error)
}

type Transition struct {
    Next   WorkflowState
    Reason string
}
```

После каждого успешного перехода case атомарно сохраняется.

## 8. Ключевые переходы

```text
CHECK_AFFECTED:
  VersionAffected == FALSE -> EVALUATE_VERDICT
  otherwise                -> RESOLVE_ROOT_CAUSE

RESOLVE_ROOT_CAUSE:
  RESOLVED  -> BUILD_EXPLOIT_MODEL
  AMBIGUOUS -> INCONCLUSIVE
  NOT_FOUND -> INCONCLUSIVE

EVALUATE_CONDITIONS:
  all mandatory TRUE -> REVIEW
  candidate FALSE     -> NEGATIVE_CHECK
  UNKNOWN + next tool -> COLLECT_EVIDENCE
  UNKNOWN + no action -> INCONCLUSIVE

NEGATIVE_CHECK:
  VERIFIED           -> REVIEW
  INSUFFICIENT_SCOPE -> COLLECT_EVIDENCE
  unresolved         -> INCONCLUSIVE

REVIEW:
  ACCEPT -> EVALUATE_VERDICT
  REVISE -> REPAIR_ANALYSIS

REPAIR_ANALYSIS:
  targeted additional evidence -> COLLECT_EVIDENCE
```

## 9. Budgets

```go
type AnalysisLimits struct {
    MaxIterations       int
    MaxToolCalls        int
    MaxLLMCalls         int
    MaxSourceReads      int
    MaxReviewIterations int
}
```

Budget проверяется до операции. Исчерпание аналитического бюджета -> `INCONCLUSIVE`.

## 10. Error model

Разделять:

- transient;
- tool failure;
- invalid input;
- unsupported analysis;
- internal failure.

Tool failure обычно формирует limitation и UNKNOWN. `FAILED` используется только когда workflow невозможно продолжить инфраструктурно.

## 11. CLI MVP

```text
vuln-analyzer analyze \
  --repo /src/product \
  --vuln GO-XXXX-YYYY \
  [--goos linux] \
  [--goarch amd64] \
  [--build-tags tag1,tag2] \
  [--root-cause pkg.Symbol] \
  [--exploit-model exploit-model.json] \
  [--deterministic-only]
```

Manual input проходит verification и не считается автоматически доверенным.

## 12. Главный архитектурный запрет

Не вводить скрывающий всё интерфейс вида:

```go
type SecurityAgent interface {
    AnalyzeRepository(...) string
}
```

Основной продукт — `AnalysisCase + EvidenceGraph + Claims + Verdict`, а не prose-ответ модели.
