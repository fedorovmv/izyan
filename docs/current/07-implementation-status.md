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
- provenance: forward tracing в тело callee — opaque call резолвится до
  FuncDecl (включая stdlib/deps через on-demand load), результат
  доказывается выведенным из параметров/констант; тело с чтением внешних
  источников (os.Args, http.Request, known source funcs) → UNKNOWN.
  Whitelist имён не используется — «pure» доказывается структурно.

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
- Полностью автоматический прогон `analyze --repo . --vuln GO-2025-3595`
  (без root-cause и без exploit-model): grouped model из 6 sink-ов,
  `os.Args` input → EXPLOITABLE; constant input → NO_EXPLOIT_PATH_FOUND.

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
  авто root cause из advisory symbols → тот же verified путь;
  авто exploit model → grouped conditions → verified FALSE.
- fixtures: `testdata/{constprod,extprod,funcvalprod,validprod,dep}`.

## Slice 5 — Exploit Model automation (done, deterministic part)

- `internal/exploit.Builder`: ExploitModel из RootCauseModel — advisory
  symbols это МНОЖЕСТВО альтернативных sink-ов одного механизма, поэтому
  модель групповая: один `C-REACH` (Subjects: все sink-и, TRUE по любому)
  + один `C-INPUT` (ATTACKER_CONTROL при совпадающем input-arg, иначе
  INPUT_CONSTRAINT по всем аргументам, ArgIndex=-1).
- `Condition.Subjects []SymbolRef` — grouped semantics во всех слоях:
  evaluator, provenance collector, negative verifier.
- `goanalysis.InputParamIndex`: выбор input-аргумента по сигнатуре
  (http.Request > io.Reader > []byte/string > слайсы); -1 при
  неразрешимости → all-args trace, не догадка.
- `TraceAllArguments` для ArgIndex<0; verifier проверяет все call sites
  всех subject-ов.
- `--exploit-model` теперь опционален: без него модель строится из
  root cause; без root cause resolver-а по-прежнему INCONCLUSIVE.

Не входит: LLM ExploitModelBuilder, semantic evaluator, gap-driven
Planner — слоты готовы, детерминистический контур закрыт.

Оставшийся срез — Slice 6: Reviewer + bounded repair loop + tracker
adapter.
## Slice 6 — Reviewer + bounded repair + tracker adapter (done, deterministic)

- `internal/review.Structural`: аудит immutable-пакета перед вердиктом —
  TRUE без evidence, FALSE без/противоречащий negative verification,
  dangling evidence-ссылки, exploit model без root cause, сильный вердикт
  при tool limitations. Результат ACCEPT/REVISE + structured findings;
  verdict reviewer не выставляет (спека §21).
- `states.Review`: proposed verdict считается детерминистически, REVISE →
  bounded repair = демоция claim-ов с high-findings до UNKNOWN (repair
  только убирает неподдержанную силу, никогда не добавляет). Бюджет:
  `MaxReviewIterations` (default 2), исчерпание → limitation + verdict на
  repaired claims. Найден и закрыт маршрутный баг: NEGATIVE_CHECK раньше
  прыгала прямо в EVALUATE_VERDICT минуя REVIEW.
- `internal/tracker.Sink` + `FileSink`: tracker-ready markdown публикуется
  в `tracker_comment.md` рядом с report; сбой публикации → tool
  limitation, не fail. Слот для реального адаптера (SberTrack и т.п.) —
  без изменения workflow.
- report.md: секция `## Review` (результат + findings по каждому REV-*).
- Тесты: reviewer unit (7 кейсов), repair-демоция TRUE→UNKNOWN, budget
  exhausted → limitation; e2e прогон теперь всегда проходит REVIEW.
- Live GO-2025-3595: REV-1 ACCEPT + tracker_comment.md записан.

Не входит: LLM-Reviewer поверх `review.Reviewer` интерфейса, реальный
tracker API sink.

## LLM layer — adapters over deterministic core (done)

- `internal/llm`: OpenAI-compatible client (`POST /chat/completions`,
  temperature=0, max_tokens/timeout/insecure-TLS из env), `LoadDotEnv`
  (`.env`: --llm-env, cwd или repo), `ExtractJSON` толерантен к
  ```json-фенсам. Две модели: LLM_BUILD_MODEL (генерация структур) и
  LLM_ANALYZE_MODEL (рассуждения/review).
- `llm.RootCauseResolver`: deterministic resolver сначала; LLM propose
  candidates только при NOT_FOUND/AMBIGUOUS → каждый проходит
  rootcause.Verifier по dep source (непроверенные → alternatives/
  limitations). Префикс `pkgname.` в symbol нормализуется.
- `llm.ExploitModelBuilder`: LLM предлагает условия → валидация
  (kind ∈ enum, subjects ⊆ root-cause sinks) → merge с детерминистической
  базой (C-REACH/C-INPUT гарантированы) → при любой ошибке fallback.
- `llm.Reviewer` + `review.Multi`: LLM аудит пакета, findings сливаются со
  Structural; REVISE любого источника → bounded repair.
- Бюджеты: `Usage.LLMCalls` инкрементится на каждый вызов,
  `MaxLLMCalls` (<=0 = без явного лимита; CLI ставит 32).
  `--deterministic-only` гасит LLM-слой полностью.
- Инвариант сохранён: LLM-текст не evidence; все LLM-результаты проходят
  детерминистическую верификацию до влияния на вердикт.

### Live-проверка (Qwen, api.ai.sbt)

- GO-2025-3595 full-auto: build-модель добавила `C-CONSTRAINT`
  (INPUT_CONSTRAINT — unquoted attr + `/` → self-closing; реальная
  механика CVE) к детерминистическим C-REACH/C-INPUT → NO_EXPLOIT_PATH_FOUND.
- Advisory без symbols: LLM предложил Parse/ParseFragment/Tokenizer.Read →
  verifier подтвердил 2/3 (Tokenizer.Read не существует → limitation) →
  полный пайплайн → вердикт корректный.
- Analyze-модель 404 (не развёрнута на инфре): honest low-severity finding
  в review, пайплайн не ломается.
- Unit: mock-сервер, 8 кейсов llm-пакета.

## LLM agent loop — Slice 7 (done)

- `llm.Tools`: typed tools поверх goanalysis.Index — read_function,
  find_symbol, find_callers, find_entrypoints, trace_argument,
  find_validations, scan_dynamic. Каждый вызов бюджетится
  (MaxToolCalls/MaxSourceReads) и регистрирует DETERMINISTIC evidence;
  ошибка инструмента возвращается модели как error, не как «нет данных».
- `llm.ClaimEvaluator` (evaluator.ConditionEvaluator): bounded loop
  (MaxSteps=8) per condition — модель выбирает tool_calls или claim;
  transcript короткий, per-condition (спека §20); TRUE принимается
  только с evidence_ids ⊆ графа, FALSE идёт через negative verifier.
- `states.EvaluateConditions.Fallback`: агент вызывается только на
  UNKNOWN после детерминистических оценщиков.
- Live GO-2025-3595: build-модель предложила C-ATTR-SOLIDUS +
  C-FOREIGN-CONTENT (семантические условия), analyze-модель
  (Qwen3.6-35B-A3B) совершила tool calls, LLM-ревью вернуло REVISE с
  findings по scope evidence. Вердикт сохранил NO_EXPLOIT_PATH_FOUND —
  на verified FALSE по C-INPUT.
- Тесты: scripted mock-server — claim через tool evidence, отклонение
  TRUE без evidence, остановка по step-бюджету.

Осталось: CONDITION-EVAL для других доменов (CONFIGURATION источники,
build-tag развёртка), реальный tracker sink, P6 remediation.

## Добивка Slice 7 (done)

- `evaluator.Validation`: VALIDATION-условия по DataFlows+Validations —
  гарды перед sink на всех call sites → FALSE-кандидат (negative
  verification обязателен); частичное/нулевое покрытие → UNKNOWN.
  Отсутствие гардов не доказывает отсутствие валидации.
- `LLM_BUILD_MAX_RETRIES` теперь реально работает: build-модель повторяет
  запрос при непарсящемся JSON (rootcause + exploit builders).
- Фикстура из плана — tool-failure: `TestE2EGovulncheckFailure` —
  ошибка runner-а не даёт FALSE, C-REACH UNKNOWN → INCONCLUSIVE
  (на extprod, где C-INPUT TRUE — единственный обход был бы ложный FALSE).
- Тесты: +3 validation, +1 tool-failure e2e, +1 build-retry.

## Deployment-dependent provenance + fixture matrix (done)

- `evaluator.ArgumentOrigin`: CONFIGURATION/DATABASE/INTERNAL_SERVICE
  origins больше не идут в FALSE — это deployment-trust-boundary, не
  доказуемо «не под контролем атакующего» (спека §12). Только
  CONSTANT/GENERATED → FALSE-кандидат; deploy-dependent → UNKNOWN.
- `goanalysis.Verifier` выровнен: те же origins теперь CONTRADICTED
  для FALSE-claim input-условий (было: verified).
- Новая фикстура `testdata/configprod` (flag → sink) → C-INPUT UNKNOWN →
  INCONCLUSIVE. `TestE2EAmbiguousRootCause`: advisory symbol отсутствует
  в dep source → AMBIGUOUS → INCONCLUSIVE. Матрица фикстур из плана
  закрыта: constprod/extprod/funcvalprod/validprod/configprod +
  tool-failure + ambiguous-root-cause.

## Remediation (done)

- report.md: секция `## Remediation` — минимальная fixed-версия строго
  выше resolved (semver compare, нормализация v-prefix), `go get`/`go mod
  tidy` команда; нет фикса → honest "no fixed version published".
  Не affected → секция отсутствует. Live: x/net v0.32.0 → v0.38.0.
- Tracker adapter остаётся generic: `tracker.Sink` интерфейс + `FileSink`
  (tracker_comment.md); конкретные адаптеры (GitHub Issues, GL, и пр.)
  добавляются позже без изменения ядра.

## Batch scan (done)

- `vuln-analyzer scan --repo <path>`: `go list -m all` → OSV `/v1/query`
  по каждому зависимому модулю (ecosystem Go) → dedupe → пер-advisory
  полный пайплайн → `scan.json` рядом с кейсами. `--max-vulns` cap
  (default 50), `--deterministic-only`, все общие флаги.
- Дешёвый pre-filter перед полным движком: `affected.GoResolver` по
  снапшоту — любой детерминистический FALSE в цепочке
  module/version/package/build → строка `FILTERED` + `NOT_AFFECTED`
  в отчёте без запуска движка. Выжившие идут через `analyzeCase`
  целиком (LLM-агент, ревью, вердикт, per-case reports).
- Per-advisory сбой → `ERROR` строка, не крашит скан и не даёт ложный
  вердикт.
- Live: product на x/net v0.32.0 → 100+ advisories, ~96 отфильтрованы
  дешёво, 4 выживших прошли полный анализ (GO-2025-3595 →
  NO_EXPLOIT_PATH_FOUND).
- Тесты: QueryOSV (body shape, ids, error status, empty), dedupeAppend,
  deterministicallyNotAffected для каждого звена цепочки.
