# Governing specification: модуль анализа эксплуатируемости уязвимостей

## 1. Назначение

Сервис на Go анализирует уязвимость относительно конкретного snapshot продукта и формирует воспроизводимый verdict с доказательствами.

Ключевой вопрос: не «достижима ли уязвимая функция?», а «выполняются ли обязательные условия эксплуатации конкретной уязвимости?». Reachability является одним из условий, но не заменяет exploitability analysis.

## 2. Архитектура

```text
Task Tracker
  -> Vulnerability Intake
  -> Affected Resolver
  -> Root Cause Resolver
  -> Exploit Condition Builder
  -> Evidence Pipeline
  -> EvidenceGraph
  -> Condition Evaluator
  -> Negative Check
  -> Reviewer
  -> Deterministic Verdict Engine
  -> Report
```

Remediation — отдельный workflow.

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

Persisted `AnalysisCase`, а не LLM conversation, является источником истины.

## 4. ProductSnapshot

Любой вывод привязан к конкретному состоянию продукта:

- repository;
- commit/tag;
- Go version;
- GOOS/GOARCH;
- build tags;
- CGO;
- vendor mode;
- `go.work`;
- `replace` directives.

Без конкретного commit/tag финальный verdict запрещён.

## 5. Vulnerability model

Нормализуются:

- CVE/GO/GHSA и aliases;
- module/package;
- affected ranges;
- fixed versions;
- affected symbols;
- description/summary;
- CWE;
- references;
- provenance каждого существенного поля.

Источники: Go Vulnerability Database, OSV, GHSA/vendor advisory, task tracker, внутренние источники.

## 6. Affected Resolver

Дешёвые детерминированные проверки выполняются первыми:

```text
dependency exists?
 -> affected version?
 -> package present?
 -> relevant build?
```

Используются `go list -m -json all`, `go list -deps -json`, `go mod graph` и build context.

Если версия вне affected range — `NOT_AFFECTED` без LLM-heavy анализа.

## 7. RootCauseModel

Root cause — самостоятельная проверяемая сущность:

```go
type RootCause struct {
    Package     string
    Symbol      string
    Role        RootCauseRole
    Mechanism   string
    EvidenceIDs []EvidenceID
}
```

Статусы: `RESOLVED`, `AMBIGUOUS`, `NOT_FOUND`.

Приоритет источников:

1. явные affected symbols;
2. fix commit/patch;
3. vulnerable source;
4. vendor advisory;
5. CVE description/CWE.

LLM формирует кандидатов, но кандидат обязан пройти verification: symbol exists, принадлежит affected package, patch/source подтверждают механизм. Неоднозначный root cause приводит к `INCONCLUSIVE`.

## 8. ExploitModel

После root cause строится минимальный набор обязательных условий эксплуатации.

```go
type ExploitModel struct {
    Impact              string
    RootCauses          []RootCauseRef
    MandatoryConditions []Condition
    SupportingFactors   []Condition
    EvidenceIDs         []EvidenceID
}
```

Условие должно быть атомарным и проверяемым. Примеры:

- `SYMBOL_REACHABLE`;
- `ATTACKER_CONTROL`;
- `INPUT_CONSTRAINT`;
- `VALIDATION_PRESENT/ABSENT`;
- `CONFIGURATION`;
- `BUILD_CONDITION`;
- `PLATFORM_CONDITION`;
- `AUTHENTICATION/AUTHORIZATION_CONDITION`;
- `RUNTIME_CONDITION`.

`MandatoryConditions` участвуют в verdict. `SupportingFactors` влияют только на risk/priority/report.

## 9. Exploit Pattern Library

Для типовых классов уязвимостей хранятся шаблоны вопросов, а не готовые verdict:

- panic/DoS;
- malformed input/OOB;
- path traversal;
- command injection;
- SSRF;
- unsafe deserialization;
- resource exhaustion;
- auth bypass/XXE/ReDoS по мере необходимости.

LLM адаптирует шаблон по advisory + patch + source.

## 10. Evidence

Факт из инструмента сохраняется как самостоятельный объект:

```go
type Evidence struct {
    ID           EvidenceID
    Kind         EvidenceKind
    Quality      EvidenceQuality
    Source       string
    Repository   string
    Commit       string
    File         string
    StartLine    int
    EndLine      int
    Tool         string
    ToolVersion  string
    Command      string
    Content      string
    ArtifactHash string
    Limitations  []string
}
```

Качество:

- `AUTHORITATIVE` — advisory/fix commit/официальные affected symbols;
- `DETERMINISTIC` — go list/govulncheck/build/runtime trace;
- `STRUCTURAL` — AST/SSA/call graph/data-flow;
- `HEURISTIC` — regex/proximity/pattern search;
- `LLM_INFERRED` — интерпретация модели.

`LLM_INFERRED` не может самостоятельно подтверждать Condition.

## 11. EvidenceGraph

Raw outputs анализаторов нормализуются в стабильный versioned contract:

```text
EvidenceGraph
  - Evidence
  - CallPaths
  - DataFlows
  - Entrypoints
  - Validations
  - Configuration
  - Runtime
  - ToolLimitations
  - Hash
```

Raw tool output хранится отдельно. EvidenceGraph должен быть deterministic, hashable и serializable.

## 12. Claims

Каждый mandatory Condition получает один текущий Claim:

```go
type Claim struct {
    ID                   ClaimID
    ConditionID          ConditionID
    Result               ClaimResult // TRUE/FALSE/UNKNOWN
    EvidenceIDs          []EvidenceID
    Explanation          string
    Limitations          []string
    NegativeVerification *NegativeVerification
}
```

Запрещены промежуточные псевдовердикты `LIKELY_TRUE`, `PROBABLY_SAFE` и т.п.

## 13. Правила TRUE/FALSE/UNKNOWN

`TRUE` требует положительного evidence.

`FALSE` требует более строгого положительного доказательства невозможности обязательного условия.

Главный инвариант:

```text
NO EVIDENCE != FALSE
```

Если путь не найден, но полнота анализа не доказана, Condition остаётся `UNKNOWN`.

Для сильного `FALSE` необходимо покрыть relevant callers/sources/configuration и существенные dynamic alternatives.

`UNKNOWN` — нормальный результат при reflection, unsafe, plugins, unresolved interfaces/function pointers, неизвестной конфигурации, недоступном runtime evidence, tool failure или исчерпании бюджета.

## 14. Go-specific analysis

В MVP основной источник reachability — `govulncheck` + Go Vulnerability Database.

Он используется для:

- affected module/package/symbol;
- call stacks/reachability;
- базовой связи уязвимости с программой.

Собственные `go/packages`, `go/ssa`, `go/callgraph`, `go/ast`, `go/types` применяются только для вопросов, которых `govulncheck` не закрывает: argument provenance, validation, alternate callers, entrypoints, configuration.

Полноценный универсальный taint engine в MVP не нужен.

## 15. Data origin / data flow

Origin классифицируется как:

- `EXTERNAL_UNTRUSTED`;
- `EXTERNAL_AUTHENTICATED`;
- `CONFIGURATION`;
- `DATABASE`;
- `INTERNAL_SERVICE`;
- `CONSTANT`;
- `GENERATED`;
- `UNKNOWN`.

`authenticated != trusted`, если пользователь контролирует значение.

Целевая форма анализа:

```text
source -> transformations -> validation -> sink
```

Важны security-relevant transformations, а не только начало и конец.

## 16. Validation analysis

Название функции `validate()` не является доказательством. Проверяется конкретное свойство, связанное с exploit precondition.

Если CVE требует `len(input) < 4`, доказательством mitigation является логика, гарантирующая `len(input) >= 4` до sink, а не общий факт «input validated».

## 17. Tool API

LLM работает только через типизированные инструменты:

- `get_vulnerability`;
- `get_advisory`;
- `get_fix_references`;
- `get_fix_diff`;
- `get_module_version`;
- `get_dependency_graph`;
- `run_govulncheck`;
- `find_symbol`;
- `find_references`;
- `find_callers`;
- `find_entrypoints`;
- `read_function`;
- `read_source`;
- `trace_argument`;
- `find_validations`;
- `search_source`;
- `run_build`;
- `run_tests`.

Universal shell не является основным интерфейсом агента.

Каждый аналитический tool call привязан к `ConditionID`, `HypothesisID` и purpose.

Tool failure — не отрицательное evidence.

## 18. Hypothesis-driven loop

```text
select UNKNOWN condition
 -> formulate hypothesis
 -> call targeted tool
 -> store Evidence
 -> update EvidenceGraph
 -> evaluate claim
 -> gap analysis
```

Оркестратор на Go управляет state, permissions, budgets, schema validation, persistence, retry/timeout. LLM выбирает, что проверить и как семантически интерпретировать полученный контекст.

## 19. Negative-check

Перед safe verdict каждый `FALSE`, влияющий на него, проходит попытку опровержения:

- альтернативные callers;
- interface implementations;
- function variables;
- runtime registration;
- reflection/unsafe;
- build-tagged implementation;
- alternate entrypoints;
- configuration overrides.

Результаты: `VERIFIED`, `INSUFFICIENT_SCOPE`, `CONTRADICTED`.

Только `VERIFIED` допускает использование `FALSE` для `NO_EXPLOIT_PATH_FOUND`.

## 20. Verdict Engine

Verdict вычисляется чистой Go-функцией:

```text
affected version FALSE
    -> NOT_AFFECTED

all mandatory TRUE
    -> EXPLOITABLE

mandatory FALSE + negative verification VERIFIED
    -> NO_EXPLOIT_PATH_FOUND

otherwise
    -> INCONCLUSIVE
```

Confidence, CVSS, EPSS, KEV и PoC availability не участвуют в этом вычислении.

## 21. Reviewer

Reviewer получает immutable package:

- Vulnerability;
- ProductSnapshot;
- RootCauseModel;
- ExploitModel;
- EvidenceGraph;
- Claims;
- proposed Verdict.

Он проверяет:

- root cause;
- пропущенные mandatory conditions;
- unsupported TRUE/FALSE;
- missed caller/entrypoint;
- неправильную интерпретацию patch;
- scope mismatch;
- dynamic behavior;
- противоречия evidence.

Reviewer возвращает `ACCEPT` или `REVISE` с конкретными findings; новый verdict он не выставляет. Repair loop ограничен 1–2 итерациями.

## 22. Persistence/reproducibility

Сохраняются:

```text
case/
  vulnerability
  product_snapshot
  affected_analysis
  root_cause_model
  exploit_model
  hypotheses
  tool_executions
  evidence_graph
  claims
  reviews
  verdict
  report
```

Для tool execution фиксируются version/input/command/exit status/stdout/stderr/commit/build configuration/hash.

## 23. Autonomy budget

Минимальные лимиты:

- MaxIterations;
- MaxToolCalls;
- MaxLLMCalls;
- MaxSourceReads;
- MaxReviewIterations.

Исчерпание аналитического бюджета приводит к `INCONCLUSIVE`, а не к догадке.

## 24. Remediation

Не входит в критический путь MVP, но архитектура должна позволять:

```text
EXPLOITABLE
 -> fixed version
 -> isolated worktree
 -> dependency upgrade
 -> go mod tidy
 -> build/tests/govulncheck
 -> minimal compatibility repair if needed
 -> repeat exploitability analysis
```

## 25. Output

Внутренняя модель не должна зависеть от VEX. Выходы:

- JSON artifact;
- human-readable report;
- task tracker comment;
- позднее OpenVEX/CycloneDX VEX.

## 26. MVP acceptance criteria

MVP готов, если:

1. анализ всегда привязан к ProductSnapshot;
2. affected version определяется без LLM;
3. RootCauseModel существует отдельно и имеет evidence;
4. ExploitModel содержит проверяемые mandatory conditions;
5. raw tool output нормализуется в EvidenceGraph;
6. claims только TRUE/FALSE/UNKNOWN;
7. absence of evidence не становится FALSE;
8. safe FALSE проходит negative-check;
9. tool failure не становится negative evidence;
10. confidence/CVSS/EPSS/KEV не участвуют в verdict;
11. LLM не может напрямую задать итоговый verdict;
12. Reviewer проверяет root cause/conditions/claims;
13. `INCONCLUSIVE` является штатным результатом;
14. persisted state позволяет продолжить анализ без LLM chat history;
15. evidence воспроизводимо;
16. формируется tracker-ready rationale.

## 27. Главные инварианты

```text
dependency present != exploitable
vulnerable function reachable != exploitable
path not found != path impossible
LLM statement != Evidence
high confidence != proof
```

Безопасный verdict требует положительного доказательства невозможности хотя бы одного обязательного условия эксплуатации.
