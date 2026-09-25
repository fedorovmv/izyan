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

Не хватает до конца среза: фиксируемые EvidenceKind-контракты для всех
collectors и golden fixtures из плана §5.

## Проверено end-to-end

- `NOT_AFFECTED`: модуль отсутствует в графе зависимостей реального repo.
- `EXPLOITABLE`: реальный GO-2025-3595 на `golang.org/x/net@v0.32.0` —
  OSV API → go list → govulncheck trace `main → html.Parse` →
  TRUE claim → deterministic verdict.
- `INCONCLUSIVE`: affected=TRUE, но govulncheck не нашёл call path →
  FALSE-кандидат без negative verification.

## Тесты

- unit: semver ranges, OSV-маппинг, verdict matrix, affected resolver
  на fake GoTool.
- golden e2e (`internal/states`): NOT_AFFECTED через реальные
  `go list`+git fixture; affected → INCONCLUSIVE; SYMBOL_REACHABLE TRUE;
  no-path → кандидат-FALSE → INCONCLUSIVE.

## Следующий вертикальный срез — Slice 3 (source analysis)

1. `find_symbol`/`find_callers`/`read_function`/`find_entrypoints` через
   `go/packages`+AST — targeted tools для условий без govulncheck-покрытия.
2. `trace_argument` (argument provenance) + `find_validations` для
   `ATTACKER_CONTROL`/`INPUT_CONSTRAINT`/`VALIDATION` conditions.
3. Настоящий negative verifier: альтернативные callers, interface
   implementations, reflection/unsafe markers → `VERIFIED` для FALSE.
4. Golden fixtures из плана §5: reachable-but-validated,
   interface/dynamic-path, tool-failure.

Дальше: Slice 4 (FixResolver/PatchProvider + LLM RootCauseResolver) и
Slice 5 (ExploitModelBuilder + semantic ConditionEvaluator + Planner)
подключают LLM через typed tools; оркестратор, бюджеты и persisted state
уже готовы.
