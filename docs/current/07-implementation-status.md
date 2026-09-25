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

## Slice 4 — Root Cause automation (done, deterministic part)

- `internal/fix`: FixResolver (FIX/ADVISORY/WEB references → commit/patch
  URLs), HTTPProvider (github `.patch`, googlesource `^!/?format=TEXT`,
  go.dev/cl → Gerrit `patch?download`, base64-decode), unified-diff парсер
  (`diff --git` + `@@` hunks → changed files/symbols, .go only, tests skipped).
- `internal/rootcause.Resolver`: кандидаты по приоритету спеки —
  advisory `affected_symbols` (AUTHORITATIVE evidence), затем функции,
  изменённые fix-патчем (FIX_DIFF evidence). Нет кандидатов → NOT_FOUND.
- `internal/rootcause.Verifier`: каждый кандидат проверен —
  символ существует в dep (goanalysis.Index.FindSymbol, module cache
  aware) и принадлежит affected package; неверифицированные →
  Alternatives; все отвергнуты → AMBIGUOUS → INCONCLUSIVE.
- `states.ResolveRootCause`: `--root-cause` → manual с верификацией;
  иначе авто-пайплайн; RESOLVED → продолжение, остальное → INCONCLUSIVE.
- provenance: whitelist pure-функций stdlib (strings.NewReader,
  fmt.Sprintf, strconv.Itoa, ...) — origin аргументов пропагирует через
  них; неизвестные вызовы по-прежнему UNKNOWN.

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
- `NO_EXPLOIT_PATH_FOUND` на реальном GO-2025-3595 без `--root-cause`:
  авто-резолв 6 advisory-символов (html.Parse, ParseFragment, ...),
  верификация в x/net module cache, govulncheck trace TRUE для C-REACH,
  provenance `html.Parse(strings.NewReader("<p>x</p>"))` → CONSTANT →
  C-INPUT verified FALSE. «Reachable but mitigated» — полностью
  автоматический пайплайн.

## Тесты

- unit: semver ranges, OSV-маппинг, verdict matrix, affected resolver
  на fake GoTool; goanalysis: FindSymbol/FindCallers/TraceArgument
  (constant/external/param-hop)/FindValidations/ScanDynamic/FindEntrypoints;
  fix: patchURL/patch parse/fix refs; rootcause: resolver/verifier на
  fixtures.
- golden e2e (`internal/states`): NOT_AFFECTED; affected → INCONCLUSIVE;
  SYMBOL_REACHABLE TRUE; no-path → кандидат-FALSE → INCONCLUSIVE;
  constprod → verified FALSE → NO_EXPLOIT_PATH_FOUND;
  extprod (os.Args) → ATTACKER_CONTROL TRUE → EXPLOITABLE;
  funcvalprod (func-value escape) → CONTRADICTED → INCONCLUSIVE;
  авто root cause из advisory symbols → тот же verified путь.
- fixtures: `testdata/{constprod,extprod,funcvalprod,validprod,dep}`.

## Следующий вертикальный срез — Slice 5

1. ExploitModelBuilder: паттерны mandatory conditions из root cause
   (SymbolReachable для SINK + ATTACKER_CONTROL для аргументов + …),
   авто-генерация `--exploit-model` если не задан.
2. Semantic ConditionEvaluator и gap-driven Planner поверх typed tools.
3. Reviewer + bounded repair loop (Slice 6), tracker adapter.

LLM-стадии подключаются поверх тех же typed tools (`goanalysis.Index` —
backend); вердикт остаётся чистой функцией от claims.
