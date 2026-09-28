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

## 3. Отсутствует концептуально — сканер обязан, но не делает

### 3.1 Deployment/exposure как факт, не caveat — `done` (первый слой)

Реализовано по [`dev/plans/exposure-facts-plan.md`](../plans/exposure-facts-plan.md): `runExposure` в
CollectEvidence собирает `ExposureFact` — inbound listener-сайты
(`net.Listen*`/`http.Server`/`grpc`) с резолвом bind-аргумента
(literal/const/var/field/env) и outbound dial-сайты в уязвимый модуль;
`env:`-источники дозрезолвляются `exposure.ScanRepo` по конфигам
репозитория; `Scope` = static/configured/unknown. Supporting-условие
`C-EXPOSURE` (`check=exposure`) в peer-driven и NIL_DEREF паттернах
получает claim и секцию «Exposure facts» в отчёте — не гейтит вердикт.

Не покрыто: auth middleware на entrypoint'ах, k8s/docker-манифесты,
связывание `var:`/`field:`-источников с конкретными config-значениями
(только `env:` мэтчится по имени ключа), разделение `0.0.0.0`/`127.0.0.1`
на mandatory-уровне (scope есть, в вердикт не идёт — осознанно).

### 3.2 Pattern library / vuln-class exploit models — `done` (базовый слой)

Реализовано по [`dev/plans/pattern-library-plan.md`](../plans/pattern-library-plan.md): классификатор (CWE →
keywords → fix-diff), декларативный `exploit.Registry`, `Condition.Params`
для evaluator-семантики, ветки сбора/оценки/фальсификации
(`check=symbol_present`, `direction=read`, `sequence=a->b`,
`input_source=peer`), отображение класса и параметров в отчёте.

Закрытые мотивирующие кейсы:

- credential/secret-in-memory (GHSA-27gv) — `INFO_LEAK`:
  `C-DATA-PRESENT` (поля подтверждаются `FindSymbol` в dep source) +
  `C-EXPOSED` (product-читатели `Type.Field` через `SearchSymbol`;
  e2e: нет читателя → VERIFIED FALSE → NO_EXPLOIT_PATH_FOUND, есть
  читатель → EXPLOITABLE);
- URI round-trip (GHSA-465g) — `URI_CONFUSION`: `C-ROUNDTRIP`
  биндится на паре exported API и проверяет, что продукт вызывает
  обоих членов пары; неполная пара → FALSE-кандидат;
- peer-driven семейство (wire parser/OOB/int-overflow/exhaustion) —
  `C-PEER-INPUT`+`C-CONSTRAINT` (+supporting `C-EXPOSURE`) вместо
  generic input;
- NIL_DEREF — `C-TRIGGER`+`C-HOT-PATH` (+supporting `C-EXPOSURE`).

Остаток: остальные классы (PATH_TRAVERSAL, INJECTION, SSRF, AUTH_BYPASS,
XXE, REDOS, RACE, DESERIALIZATION) классифицируются, но сидят на
generic-модели — паттерны добавляются по мере живых кейсов. `bound`
верифицируется формально: sanitize-гарды несут enforce'нутый числовой
диапазон (`Validation.BoundLow/BoundHigh`, вкл.; literal/const/конверсии
`T(lit)` резолвятся, неразрешённый порог → nil, односторонность
сохраняется, по нескольким write-site'ам union-диапазон). Evaluator
разбирает `params.bound` в дизъюнкты `var op lit` (`or`/`||`/`,`/`&&`),
связывает var→arg позиционно и по имени в guard.Property, и FALSE +
«bound verified» выдаётся только когда каждый дизъюнкт численно
контрадиктит записанному диапазону; нераспарсенные термы → limitation,
не FALSE-буст. Обратный случай: константный аргумент, удовлетворяющий
дизъюнкту (`DataFlow.Value`), даёт детерминированный TRUE — константа
нарушает bound, никакой гард её не спасает (проверяется до guard-пути).

Дополнительно после живого перепрогона: subject-пулы по `Bind`-оси —
INFO_LEAK биндит datum-субъекты (advisory-символы `Type.Field` +
`SensitiveFields` field-scan dep package + верифицированные LLM-
предложения), URI_CONFUSION достраивает пару stem-таблицей
(`URI.String→ParseURI`). Проверено на живых кейсах: GHSA-27gv биндит
реальные поля (`PlainAuth.Password`, `Config.SASL`, …), GHSA-465g —
реальную пару; оба VERIFIED FALSE демотированы ревьюером по reflect-
маркеру → INCONCLUSIVE (reflect действительно читает exported-поля —
консервативно верно).

### 3.3 Build/tag вариативность — `done` (первый слой)

`Index.GatedRefs` (по [`dev/plans/negative-coverage-plan.md`](../plans/negative-coverage-plan.md)) сканирует
`pkg.IgnoredFiles` — файлы, исключённые текущими build tags, — синтаксически
по импорту пакета субъекта; `_test.go` отфильтровываются. Находка
деградирует VERIFIED FALSE в INSUFFICIENT_SCOPE: путь под `-tags foo`
больше не невидим. Не проверяется компилируемость tag-варианта.

### 3.4 Interface-implementation paths — `done` (первый слой)

`Index.InterfaceDispatchSites` находит `x.Method()`-вызовы по
интерфейсному типу, который реализует тип субъекта (`types.Implements`,
оба receiver-варианта). `SearchSymbol` такие сайты пропускал (selection
резолвится на интерфейс, не на impl). Находка → INSUFFICIENT_SCOPE.
Не покрыто: impl'ы интерфейсов, вызываемых внутри dep-кода; goroutine/
channel-based dispatch.

### 3.5 Multi-hop provenance через vendor internals — `done` (первый слой)

`Index` кеширует dep-пакеты (`extraPkgs`, общий fset с продуктом);
`FindDepCallers` грузит пакет subject'а и сканирует его syntax —
unexported dep-субъекты получают dep-internal call sites, у которых
раньше не было callers вообще. `callAt`, `traceParam`, `fieldOrigin`,
`fieldWriteSites`, `fieldAddressTaken` работают по scope владеющего
пакета (`callerScope`/`memberScope`): dep-функция → dep+product скан,
product-функция → product-only (callback-сюрпризов нет). Object
identity между разными `packages.Load` — через `types.Object.Id()`
(`sameObject`), pointer-сравнение ненадёжно.

Provenance пополнен под wire-цепочки: composite literal мерджит origins
элементов (раньше — `CONSTANT` wholesale, ложный non-external на
`&io.LimitedReader{R: r}`); slice-populate (`io.ReadFull(r,b)`,
`x.Read(b)` и `readIntoMethods`) пишет origin источника в dst;
receiver-mutation (`v.Write/WriteString/ReadFrom`) — origin аргумента
в receiver; peer-источники `net.Dial*`/`tls.Dial*`/`Accept` и
`Read`-методы на сетевых receiver'ах → `EXTERNAL_UNTRUSTED`;
`bufio.NewReader` — passthrough.

`collectProvenance`: product-callers пусто + все subjects unexported +
условие peer-input (`input_source=peer` или remote-формулировка) →
dep-scope scan + trace с `ConditionID`. `ServerTransportInput`:
resolved flows → `ArgumentOrigin` (dep-trace побеждает эвристику
unexported+peer-driven — в том числе в FALSE-кандидат); flows пусто
или все UNKNOWN → прежняя эвристика-fallback. NV для dep-subjects
без product callers перетрейсит те же dep-сайты; неразрешённый трейс →
INSUFFICIENT_SCOPE, никогда не FALSE.

Фикстура `testdata/dep/vuln/wire.go` + `testdata/wireprod` (replace):
corpus-кейсы `wire-dep-peer` (net.Dial→bufio→parse→subject →
EXTERNAL_UNTRUSTED → EXPLOITABLE) и `wire-dep-const` (constant →
VERIFIED-FALSE → NO_EXPLOIT_PATH_FOUND). 18/18, false-safe=0.

Не покрыто: interface dispatch внутри dep (`m.read(r)` в amqp091 —
трейс честно остаётся UNKNOWN → эвристика), goroutine/channel dispatch
(B11), глубокие generated-цепи. Trace живого amqp091 `readField`
проверен спайком — граница пира (`net.Conn`) достижима, но
interface-boundary не резолвится.

### 3.6 run_build / run_tests evidence — `done` (первый слой)

`GapAnalysis` получил case-level exec-действие `actBuildTest`: при входе
в GAP_ANALYSIS с нерешёнными mandatory claims разово выполняются
`go build` и `go test` на `./...` (через `toolaudit.Run` →
`tool_executions`; вывод сборки направлен в throwaway-dir, репозиторий
не мутируется). Результаты — `BUILD`/`TEST` evidence (exit-статус +
вывод), гипотеза в кейсе и секция «Build & test» в report.md. Падение
сборки — limitation «product does not compile … static evidence may be
unreliable»; падение тестов — limitation со ссылкой на TEST evidence.
Действие за `--allow-exec` (исполняет код репо); без флага — честный
limitation о пропуске, запуск не скрыт. Без нерешённых claims не
запускается; при повторном входе (restart) evidence-виды не
дублируются. Агентские `run_build`/`run_tests` в `llm.Tools` остаются —
та же поверхность для LLM-planner'а. Не покрыто: результат не влияет
на claims/вердикт (build failure — caveat, не демоция); «есть ли тест
именно на уязвимое поведение» не вычисляется — свита запускается
целиком, покрытие пути отдельно не оценивается.

### 3.7 Метрики / eval harness — `done` (первый слой)

Спека §9 плана: root-cause accuracy, FALSE precision, **false-safe
count** (стоп-критерий), INCONCLUSIVE rate, evidence reproducibility.

Реализовано ([`dev/plans/eval-harness-plan.md`](../plans/eval-harness-plan.md)): `internal/eval` + сабкоманда
`eval --corpus`: корпус кейсов (`eval/corpus.json` на фикстурах
`testdata/` + синтетические OSV), метрики total/errors/expect/
inconclusive/claims_fail/**false_safe**, markdown+JSON отчёты, exit 1
при false-safe/expect-fail. Первый прогон: 11 кейсов, 0 false-safe.

Не закрыто: размеченный ground truth для root-cause accuracy и FALSE
precision; живой корпус на реальных advisory; репроусибельность
evidence (hash-сравнение графов между прогонами).

### 3.8 VEX/OpenVEX/CycloneDX экспорт

§25: «позднее OpenVEX/CycloneDX VEX». `done` для OpenVEX: каждый кейс
пишет `openvex.json` рядом с report.{json,md} — `internal/report/openvex.go`,
маппинг `EXPLOITABLE`→affected, `NOT_AFFECTED`→not_affected
(component_not_present / vulnerable_code_not_present по тому, какая
ветка отвалилась), `NO_EXPLOIT_PATH_FOUND`→not_affected +
`vulnerable_code_not_in_execute_path` (выдаётся только после NV),
`INCONCLUSIVE`→under_investigation + action_statement. Product пинится
purl'ом на анализируемый коммит, уязвимый модуль — subcomponent с
resolved version. CycloneDX VEX реализован (`internal/report/cyclonedx.go`,
spec 1.5): каждый кейс пишет `cyclonedx.json` рядом с openvex.json,
маппинг `EXPLOITABLE`→exploitable, `NOT_AFFECTED`→not_affected
(code_not_present), `NO_EXPLOIT_PATH_FOUND`→not_affected +
code_not_reachable, `INCONCLUSIVE`→in_triage + detail.

### 3.9 Remediation workflow

Минимальный слой реализован (`cmd/analyzer/remediate.go`):
`vuln-analyzer remediate` → analyze → `report.FixTarget` (наименьшая
fixed-версия выше resolved) → план `go get`/`go mod tidy`/`go build`
(+`go test` по `--run-tests`); `--apply` исполняет шаги (мутирует
go.mod/go.sum — explicit opt-in) и повторяет анализ, печатая
`verdict -> verdict`. `--worktree <path>` исполняет apply в
`git worktree add --detach` и анализирует worktree — исходный checkout
не мутируется. Проверено на фикстуре: EXPLOITABLE → NOT_AFFECTED,
исходник остался на v1.0.0.

### 3.10 Intake из tracker

Generic intake реализован (`internal/tracker/intake.go` +
`--ticket <path>`): тикет несёт vulnerability id, repo, embedded
`osv`-документ или синтезируемый advisory (module + imports +
symbols + fixed_versions → минимальный OSV JSON). CLI-флаги
переопределяют поля тикета. Сетевые адаптеры конкретных трекеров
(GitHub/Jira/SberTrack) — deferred by design.

## 4. Приоритет

Бэклог §5 упорядочен по принципу «какой UNKNOWN закрывает» —
приоритет получает работа, уменьшающая число неопределённых claims.

Закрытые пункты здесь не хранятся: история изменений — в `git log`
и планах [`dev/plans/`](../plans/), текущая механика — в
[`analysis-internals.md`](analysis-internals.md). Закрытие пункта §5 =
удаление строки из бэклога в том же коммите, что закрывает работу.

## 5. Открытый бэклог (приоритетный, с done-критериями)

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
| B5 | Build-tag варианты в dep-коде | Snapshot фиксирует tag-set; claims помечаются при tag-зависимом покрытии |
| B6 | Config-gated reachability | Config-gates влияют на гарды (учтено); reachability-config — нет → conditional-reachability метка в claim |
| B7 | `AUTHENTICATION_CONDITION` per-route | Route→handler→middleware маппинг; TRUE только при покрытии конкретного handler'а |
| B8 | Bound-семантика шире | `len(x)`, `x != 0`, float, арифметика в термах; юнит-тесты каждой формы |
| B9 | Паттерны вне 4 семейств | По живым кейсам; каждый паттерн = registry entry + фикстура |

### P3 — deferred by design

| # | Пункт | Почему |
|---|-------|--------|
| B10 | Сетевые адаптеры трекеров | `--ticket` generic JSON покрывает intake |
| B11 | goroutine/channel dispatch, interface-impl внутри dep-кода | Терминальные ограничения синтаксического скана |

Процесс: пункт берётся сверху вниз; закрытие — только с done-критерием
(тест/живой кейс), после чего строка удаляется из §5 в коммите
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
