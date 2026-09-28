# Gap analysis: спеки vs реализация

Сопоставление [`dev/specs/governing-spec.md`](../specs/governing-spec.md), [`dev/specs/analyzer-agent-spec.md`](../specs/analyzer-agent-spec.md),
[`goals-scope.md`](../../goals-scope.md), [`dev/plans/mvp-implementation-plan.md`](../plans/mvp-implementation-plan.md), [`dev/decisions/architecture-decisions.md`](../decisions/architecture-decisions.md)
с кодом по состоянию на HEAD. Пометки: `done` / `partial` / `missing`.

## 1. Покрыто (проверено живыми прогонами)

- Persisted restartable `AnalysisCase`, verdict только детерминистический.
- Affected resolver: module/version/package/build + `GOOS/GOARCH` +
  `vendor/modules.txt` + `replace`.
- Root cause: advisory symbols → fix-diff → LLM-retry, каждый кандидат
  верифицирован в dep source.
- EvidenceGraph с quality-уровнями и hash; provenance у evidence и claims.
- Evaluators: `SymbolReachable`, `ServerTransportInput`, `ArgumentOrigin`,
  `Validation`, `VersionFact`.
- Negative verification (scoped): func_value/linkname → CONTRADICTED;
  reflect/unsafe/plugin → demotion только для exported.
- Review: Structural + LLM, bounded repair, защита deterministic TRUE.
- govulncheck: stream parse, receiver-matched traces, `GovulncheckCoverage`
  (covered/not_in_db через stream + vulndb-листинг GO-*), module-usage +
  `ModuleInternalReach` fallback.
- LLM-слой как опциональные адаптеры с бюджетами и fallback'ами.
- Toolchain-слои: `go.mod` минимум → `--release-go-version` → `--binary`
  (`go version -m` + `govulncheck -mode binary`).
- `tracker.FileSink` (generic), `scan` batch mode.

## 2. Частично — есть кость, не хватает мяса

| Область | Спека | Сейчас | Пробел |
|---|---|---|---|
| Exploit model | §8–9: атомарные условия по классу уязвимости | `Classify` (CWE → keywords → fix-diff) + `exploit.Registry`: peer-driven, INFO_LEAK, URI_CONFUSION, NIL_DEREF паттерны; `Condition.Params` (`input_source`, `direction=read`, `sequence=`, `bound`, `check`); generic C-REACH/C-INPUT домердживаются; LLM дополняет и заполняет пустой `bound` | Классификация keywords — score-weighted эвристика (плотность словаря, фиксируется limitation); `bound` верифицируется численно против `BoundLow/BoundHigh` гардов и `DataFlow.Value` констант (см. ниже); паттернов пока 4 семейства — PATH_TRAVERSAL/INJECTION/SSRF/etc. сидят на generic-модели |
| Condition kinds | §8 минимум 10 типов | enum есть | `PLATFORM_CONDITION`/`RUNTIME_CONDITION` — `evaluator.Platform` (params `goos`/`goarch`/`go_version` bound против snapshot-фактов; FALSE = snapshot fact → NV `verifySnapshotFalse` VERIFIED); `AUTHENTICATION_CONDITION` — `evaluator.Authentication` (auth-middleware facts + resolved listener → TRUE; никогда не FALSE — отсутствие wiring ≠ отсутствие auth: per-handler/gateway/deployment-проверки вне скана); `CUSTOM` — `evaluator.Custom` (последний в цепочке): `check=reachable`/`direction=read`/`sequence` делегируют в reachability-машинерию, `check=symbol_present|exposure|config_flag|config_key` забирают свои evaluators (kind-agnostic); без распознанных params → UNKNOWN с limitation-списком маршрутов |
| Data origins | §15: EXTERNAL_UNTRUSTED/AUTHENTICATED, CONFIGURATION, DATABASE, INTERNAL_SERVICE, CONSTANT, GENERATED | enum есть; provenance покрывает http.Request/os.Args/net/config/generated + `populateOrigin` (Scan/Unmarshal out-params), DB-драйверы по pkg path, gRPC-стабы и http-клиенты с config-endpoint → INTERNAL_SERVICE ([`dev/plans/data-origins-plan.md`](../plans/data-origins-plan.md)) | `EXTERNAL_AUTHENTICATED` различается для outbound HTTP (auth-маркеры в enclosing-функции: Authorization-заголовок, SetBasicAuth, oauth/credentials-хелперы); inbound — `Index.InboundAuthFacts` записывает auth-middleware-факты (Use/With-аргументы, grpc-interceptors, обёрнутые handler'ы в функциях с listener-сайтами; deployment-hint, не per-route доказательство); `exposure.ScanDeploy` читает k8s/helm/openshift/istio/compose-манифесты → deployment-факты (Service LoadBalancer/NodePort, Ingress/Route/Gateway, hostPort/hostNetwork, published ports; scope=all-interfaces, фиксирует окружение деплоя включая sibling-services); детекция драйверов по pkg path — эвристика, кастомные обёртки не покрыты; struct-field provenance: `x.f = rhs`/`T{f: rhs}` write-sites резолвятся (`fieldOrigin`), reflect/pointer-записи невидимы; fallback — config-decode tags (mapstructure/env/envconfig/toml/ini) → CONFIGURATION; builtin true/false/nil — CONSTANT |
| Transformations | §15: `source → transformations → validation → sink`, security-relevant transforms | `TraceArgument` даёт origin конечного аргумента | Цепочка записывается: `DataFlow.Transformations` — все вызовы, через которые проходит трейсимое значение (под mu в Trace*); security-relevant (`escape|quote|valid|check|…` по `IsSecurityTransform`) флагируются в claim limitations + секция «Data flows» в отчёте | Семантика трансформов не моделируется: opaque call → UNKNOWN (честно); sanitize-гарды (`if cmp {x=clean}`, exhaustive sanitize-switch) записываются Guard=true; field-write guards покрывают sink при всех bounded write-sites; sanitize-switch поддерживает и range-gated форму — cases сравнивают другой var `cv`, default присваивает `ident=T(cv)`, засчитывается bounded при двусторонней границе `cv` + обязательном default; accessor-обёртки `x.Bytes()`/`int(x)` в RHS разворачиваются к локалу; multi-assign merge по всем присваиваниям локала (worst-origin) + cycle-guard `traceSeen` |
| Negative check | §19: callers, **interface implementations**, runtime registration, **build-tagged code**, configuration overrides, alternate entrypoints | func_value/linkname/reflect/unsafe/plugin по scoped rules | interface-impl и build-tag покрыты (`GatedRefs`/`InterfaceDispatchSites`); `configuration overrides` — первый слой: `Index.ConfigGated` + `verifyGuardFalse` деградируют VERIFIED→INSUFFICIENT_SCOPE, когда единственное покрытие sink'а — conditional-гарда (особенно config-читающая); конфигурация, меняющая саму reachability (не гарды), — в резерве; `verifyGuardFalse` per-arg: покрытие проверяется по (sink, arg), const/generated-аргументы не требуют Covers; `verifyInputFalse` перетрейсит на `verifyHops=16` и различает UNKNOWN→INSUFFICIENT_SCOPE (нет доказательства) vs external/config-origin→CONTRADICTED; `ScanDynamic` различает write-маркеры от bare-импортов: `reflect_write` (`reflect.Value.Set*`) ослабляет guard-FALSE только при exported покрытом поле; `unsafe_write` (store через unsafe-derived deref/index: `*(*T)(unsafe.Pointer(&f))=v`) и `unsafe_ptr` (материализация `unsafe.Pointer`/`unsafe.Add` — aliased-записи неотслеживаемы) ослабляют безусловно; bare `reflect`/`unsafe` импорты для guards-claims игнорируются (import ≠ write); field-guards дополнительно отклоняют Covers при `&x.f` address-taken (pointer-записи невидимы write-site скану) |
| Typed tools | §17: 17 инструментов | все 17 реализованы в `llm.Tools` ([`dev/plans/typed-tools-plan.md`](../plans/typed-tools-plan.md)): source-инструменты + get_vulnerability/get_advisory/get_fix_references/get_fix_diff/get_module_version/get_dependency_graph/run_govulncheck/read_source/search_source/run_build/run_tests; exec-инструменты за `--allow-exec` | LLM-agent сам не выбирает инструменты (planner детерминистичен); read_source/search_source допускают product-дерево + GOMODCACHE/GOPATH module cache (dep-файлы видны как evidence) |
| Hypothesis loop | §18 + agent §6,§16: OPEN→CONFIRMED/REJECTED, gap-driven planner | `GAP_ANALYSIS` state: UNKNOWN mandatory → Hypothesis → tool action (deep-trace/ScanDynamic/dispatch-scan) → re-evaluate → fixpoint≤3/MaxToolCalls; гипотезы персистятся ([`dev/plans/gap-loop-plan.md`](../plans/gap-loop-plan.md)); deep-trace и caller-guard climb работают per-arg (`f.Arg`, не только `cond.ArgIndex`); `ReplaceDataFlow` матчит (cond, sink, arg) — deep-результат arg1 не затирает arg0; `deepTraceHops=16`; **LLM claim-fallback перенесён в конец GAP_ANALYSIS** — deterministic+planner исчерпываются раньше агента, иначе LLM-TRUE вытесняет доказуемый FALSE (rm6m: `C-CONSTRAINT` достиг `falsifier=guards`+NV VERIFIED до агента) | LLM-planner в `GAP_ANALYSIS` реализован (`llm.Planner`, multi-step bounded: ≤3 шага на condition внутри outer-loop ≤3 итераций, глобальный MaxLLMCalls; tool-miss → REJECTED и retry с другим инструментом, UNRESOLVED/unparseable → стоп); claim-fallback `llm.ClaimEvaluator` — после det-цикла, пропускается при уже-FALSE |
| Persistence | §22: hypotheses, tool_executions с version/input/cmd/exit/stdout/stderr/hash | кейс + raw govulncheck в evidence.Content + `EvidenceGraph.ToolExecutions` (tool, version, args, exit, sha256 обоих потоков, ms) через ctx-рекордер; `Evidence.ToolVersion` заполнен для govulncheck | `EvidenceGraph.Runtime` заполняется (snapshot-facts + `go version -m` build info при `--binary`); env прогонов не пишется (секреты); reproducibility-diff есть: повторный прогон того же vuln/repo в тот же case-dir сверяет stdout/stderr-хэши `tool_executions` с предыдущим кейсом (`prior_case`, RUNTIME-evidence + limitation при drift) |
| Reviewer | §21: root cause, missed conditions, patch misinterpretation, scope mismatch, contradictions | Structural проверяет: TRUE без evidence, FALSE без NV, dangling refs, model без root cause | Pattern coverage проверяется: class-matched модель без mandatory-шаблона паттерна → finding (high при отсутствии skip-limitation, medium при записанном bind-skip); не проверяются «patch misinterpretation», «scope mismatch» |

## 3. Открытый бэклог (приоритетный, с done-критериями)

Бэклог упорядочен по принципу «какой UNKNOWN закрывает» — приоритет
получает работа, уменьшающая число неопределённых claims. Закрытые
пункты здесь не хранятся: история изменений — в `git log` и планах
[`dev/plans/`](../plans/), текущая механика — в
[`analysis-internals.md`](analysis-internals.md). Закрытие пункта =
удаление строки из бэклога в том же коммите, что закрывает работу.

Критерий MVP: модуль даёт больше `govulncheck` и выдаёт доказательно
обоснованные вердикты. Приоритет P0 блокирует критерий.

### P0 — блокирует критерий

| # | Пункт | Зачем | Done-критерий |
|---|-------|-------|----------------|
| B1 | **Ground-truth разметка live-корпуса** | `expect` пиннит наблюдаемое поведение — `false-safe=0` это отсутствие регрессий, не доказательство правильности | Истинный вердикт каждого из 11 кейсов зафиксирован вручную по advisory+коду; `expect` сравнивает с истиной; метод разметки описан в [`eval/README.md`](../../../eval/README.md) |

### P1 — e2e-качество

| # | Пункт | Зачем | Done-критерий |
|---|-------|-------|----------------|
| B4 | Устойчивость repair к bogus-демоциям | LLM-ревьюер дважды демотировал VERIFIED-FALSE семантическим misread («противоречит root cause»); промпт дополнен, но защита нужна детерминистическая | Демоция VERIFIED-FALSE требует ссылки на конкретный артефакт (маркер/uncovered site/traced origin); тест на bogus-demotion |
| B13 | **Расширение корпуса доказательной базы** | Live-слой узок: 11 кейсов, 1 dep, 1 класс; нет сравнительной базы vs standalone govulncheck | ≥30 кейсов суммарно (≥4 класса, ≥3 реальных dep) через generated-manifest продукты `eval/products/` без committed уязвимых манифестов; baseline-таблица govulncheck-vs-analyzer в [`eval/README.md`](../../../eval/README.md); ground-truth файл на каждый позитивный вердикт; `false_safe=0`; план: [`dev/plans/corpus-expansion-plan.md`](../plans/corpus-expansion-plan.md) |

### P2 — глубина покрытия

| # | Пункт | Done-критерий |
|---|-------|----------------|
| B5 | Build-tag варианты в dep-коде | Snapshot фиксирует tag-set; claims помечаются при tag-зависимом покрытии; компилируемость tag-варианта проверяется, не только синтаксический импорт |
| B6 | Config-gated reachability | Config-gates влияют на гарды (учтено); reachability-config — нет → conditional-reachability метка в claim; связывание `var:`/`field:` bind-источников с config-значениями; различение `0.0.0.0`/`127.0.0.1` на уровне условия, не только supporting-scope |
| B7 | `AUTHENTICATION_CONDITION` per-route | Route→handler→middleware маппинг; TRUE только при покрытии конкретного handler'а |
| B8 | Bound-семантика шире | `len(x)`, `x != 0`, float, арифметика в термах; юнит-тесты каждой формы |
| B14 | Build/test результат не влияет на claims | `actBuildTest` пишет BUILD/TEST evidence, но build failure — caveat, не демоция claim; покрытие пути тестами не оценивается → per-vulnerability test-coverage факт или claim-оговорка |
| B9 | Паттерны вне 4 семейств | По живым кейсам; каждый паттерн = registry entry + фикстура |

### P3 — deferred by design

| # | Пункт | Почему |
|---|-------|--------|
| B10 | Сетевые адаптеры трекеров | `--ticket` generic JSON покрывает intake |
| B11 | goroutine/channel dispatch, interface-impl внутри dep-кода, глубокие generated-цепи | Терминальные ограничения синтаксического скана |

Процесс: пункт берётся сверху вниз; закрытие — только с done-критерием
(тест/живой кейс), после чего строка удаляется из §3 в коммите
закрытия; история — в `git log`, не в этом файле. Новые находки
добавляются с приоритетом, не висят в разговоре.

### Handoff notes (что читать/трогать новой сессией)

Самодостаточные задачи — можно делегировать субагенту или свежей
сессии. Общий контекст: репо плоский (`internal/` на корне, модуля
`example.com/vuln-analyzer`), репозиторий продукта задаётся через
`VA_PRODUCT_REPO` (env) или `--repo`, проверка — `go test ./...` +
`go run ./cmd/analyzer eval --corpus eval/live-corpus.json`.

- **Корпус-дрейф**: `ghsa-j497-x9hr-x34x` на продукт-референсе даёт
  INCONCLUSIVE вместо pinned EXPLOITABLE (C-PEER-INPUT UNKNOWN). Причина
  — не B12: проверено stash-прогоном; похоже, dep-scope flows (B3)
  стали резолвиться в CONSTANT → `hasResolvedFlows` гейтит transport-
  эвристику в `evaluator/transport.go`. Либо баг гейта (CONSTANT не
  должен считаться «resolved» для peer-input), либо corpus re-pin —
  решение за B1 ground-truth.
- **B4** (делегируемо): `internal/states/states.go` — repair demotes
  high-findings; `internal/goanalysis/negative.go` — VERIFIED статусы.
  Правило: demotion VERIFIED-FALSE требует `required_check`/`problem`
  со ссылкой на артефакт (marker `reflect_write`/`unsafe_*`/uncovered
  site/origin) — иначе finding понижается до advisory. Тест —
  `internal/states/` bogus-demotion case.
- **B8** (делегируемо): `internal/evaluator/provenance.go` —
  `parseBound`/`boundTerm.satisfies`/`falsifiedBy`;
  `internal/goanalysis/provenance.go` — `exprIntValue`,
  `boundsDirection`. Расширять по одной форме: `len(x)`, `x != 0`,
  float. Тесты — `provenance_bound_test.go` образец.
- **B1** (полу-делегируемо): драфт разметки можно поручить — agent
  читает advisory (`eval/live-corpus.json` ids) + evidence продукта и
  предлагает true-verdict с rationale, но финальная разметка — за
  человеком (это и есть ценность пункта).
