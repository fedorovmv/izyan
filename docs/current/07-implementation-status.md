# Статус реализации MVP

Обновляется по мере продвижения по срезам `03-mvp-implementation-plan.md`.

## Slice 1 — deterministic foundation (done)

- Полная domain-модель: `AnalysisCase`, `Vulnerability`, `ProductSnapshot`,
  `AffectedResult`, `RootCauseModel`, `ExploitModel`, `Condition`, `Claim`,
  `Evidence`, `EvidenceGraph` (CallPaths/DataFlows/Entrypoints/Validations/
  Configuration/ToolLimitations + sha256 hash), `Hypothesis`, `Review`,
  `VerdictResult`, `AnalysisLimits`.
- `VulnerabilitySource`: OSV JSON file (`--vuln-file`), OSV API client
  (`api.osv.dev`), StaticSource для тестов. Маппинг OSV → domain с
  provenance полей, парсинг SEMVER ranges (introduced/fixed/last_affected).
- `affected.GoResolver`: `go list -m -json all` + `go list -deps -test -json
  ./...` → ModulePresent / VersionAffected / PackagePresent / BuildRelevant
  (GOOS/GOARCH ограничения), каждая проверка пишет DETERMINISTIC evidence.
  `golang.org/x/mod/semver` для range matching; `replace`-aware.
- Workflow Engine + все StateHandlers:
  `CREATED → SNAPSHOT_PRODUCT → RESOLVE_VULNERABILITY → CHECK_AFFECTED →
  RESOLVE_ROOT_CAUSE → BUILD_EXPLOIT_MODEL → COLLECT_EVIDENCE →
  EVALUATE_CONDITIONS → [NEGATIVE_CHECK] → [REVIEW] → EVALUATE_VERDICT →
  BUILD_REPORT → COMPLETED`. Неготовые стадии честно уходят в INCONCLUSIVE.
- Детерминистический `VerdictEvaluator`: `NOT_AFFECTED` только по FALSE в
  affected-цепочке; `NO_EXPLOIT_PATH_FOUND` только при VERIFIED
  negative-check; иначе `INCONCLUSIVE`.
- `internal/report`: `report.json` + human-readable `report.md` с
  tracker-ready rationale.
- CLI `vuln-analyzer analyze` со всеми флагами из спеки §11
  (`--vuln-file`, `--osv-url`, `--goos`, `--goarch`, `--build-tags`,
  `--root-cause`, `--exploit-model`, `--deterministic-only`).
- Persisted case атомарно сохраняется после каждого перехода;
  MaxIterations budget в engine.

## Slice 2 — govulncheck + evidence (частично)

- `goanalysis.ExecRunner`/`Runner`: `govulncheck -json -mode source ./...`,
  парсер JSON-стрима, нормализация findings → `EvidenceGraph.CallPaths`.
- `evaluator.SymbolReachable`: `SYMBOL_REACHABLE` condition → TRUE при
  найденном trace до root-cause символа; чистый прогон без пути →
  FALSE-кандидат; tool failure → UNKNOWN.
- `NEGATIVE_CHECK` state: без verifier'а размечает FALSE-кандидатов как
  `INSUFFICIENT_SCOPE` → честный `INCONCLUSIVE`.

## Slice 3 — source analysis (done)

- `goanalysis.Index`: `go/packages`-загрузка продукта (`./...`, с типами и
  build-тегами). `FindSymbol`, `FindCallers`, `ReadFunction`,
  `FindEntrypoints` (main/init/http-handlers), `SearchSymbol`,
  `ScanDynamic` (reflect/unsafe/plugin/linkname/func_value маркеры).
- `TraceArgument`: bounded argument provenance (≤2 caller hops) —
  классификация origin: CONSTANT / EXTERNAL_UNTRUSTED / CONFIGURATION /
  GENERATED / UNKNOWN. `FindValidations`: guard-выражения над аргументом
  до sink.
- `evaluator.ArgumentOrigin`: `ATTACKER_CONTROL` по `DataFlows` —
  TRUE при external origin, FALSE-кандидат когда все call sites
  non-external, UNKNOWN при отсутствии/неразрешимых traces.
- `goanalysis.Verifier`: negative verification для FALSE-claims —
  `SearchSymbol` (нет ссылок → VERIFIED для reachability), `ScanDynamic`
  (func_value/linkname → CONTRADICTED → demote в UNKNOWN; reflect/unsafe/
  plugin → limitation), для ATTACKER_CONTROL: provenance всех call sites.
- CollectEvidence собирает DataFlows + Validations + source evidence по
  provenance-условиям; `EvidenceGraph.ComputeHash` после всех мутаций.

## Проверено end-to-end

- `NOT_AFFECTED`: модуль отсутствует в графе зависимостей реального repo.
- `EXPLOITABLE`: реальный GO-2025-3595 на `golang.org/x/net@v0.32.0` —
  OSV API → go list → govulncheck trace `main → html.Parse` →
  TRUE claim → deterministic verdict.
- `INCONCLUSIVE`: affected=TRUE, но govulncheck не нашёл call path →
  FALSE-кандидат без negative verification.
- `NO_EXPLOIT_PATH_FOUND` (живой прогон): вызов `vuln.Parse("hardcoded")`
  — C-INPUT FALSE-кандидат → verifier: все call sites non-external →
  VERIFIED → детерминистический вердикт. govulncheck при этом отсутствовал
  в PATH → C-REACH остался UNKNOWN: tool failure ≠ negative evidence.

## Тесты

- unit: semver ranges, OSV-маппинг, verdict matrix, affected resolver
  на fake GoTool; goanalysis: FindSymbol/FindCallers/TraceArgument
  (constant/external/param-hop)/FindValidations/ScanDynamic/FindEntrypoints.
- golden e2e (`internal/states`): NOT_AFFECTED; affected → INCONCLUSIVE;
  SYMBOL_REACHABLE TRUE; no-path → кандидат-FALSE → INCONCLUSIVE;
  constprod → verified FALSE → NO_EXPLOIT_PATH_FOUND;
  extprod (os.Args) → ATTACKER_CONTROL TRUE → EXPLOITABLE;
  funcvalprod (func-value escape) → CONTRADICTED → INCONCLUSIVE.
- fixtures: `testdata/{constprod,extprod,funcvalprod,validprod,dep}`.

## Следующий вертикальный срез — Slice 4

1. FixResolver/PatchProvider — pull fix commits/diffs по advisory.
2. LLM RootCauseResolver (typed tools поверх `goanalysis.Index`),
   RootCauseVerifier (символ существует, механизм не расширяется без
   evidence).
3. ExploitModelBuilder (Slice 5): паттерны обязательных условий,
   semantic ConditionEvaluator, gap-driven Planner, Reviewer.

Дальше: оркестратор, бюджеты и persisted state для LLM-стадий уже готовы;
вердикт остаётся чистой функцией от claims.
