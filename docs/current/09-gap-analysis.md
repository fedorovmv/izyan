# Gap analysis: спеки vs реализация

Сопоставление `01-governing-spec.md`, `02-analyzer-agent-spec.md`,
`00-goals-scope.md`, `03-mvp-implementation-plan.md`, `06-decisions.md`
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
| Exploit model | §8–9: атомарные условия по классу уязвимости | `Classify` (CWE → keywords → fix-diff) + `exploit.Registry`: peer-driven, INFO_LEAK, URI_CONFUSION, NIL_DEREF паттерны; `Condition.Params` (`input_source`, `direction=read`, `sequence=`, `bound`, `check`); generic C-REACH/C-INPUT домердживаются; LLM дополняет и заполняет пустой `bound` | Классификация keywords — эвристика (фиксируется limitation); `bound` пока текстовая аннотация без доказательства гарды; паттернов пока 4 семейства — PATH_TRAVERSAL/INJECTION/SSRF/etc. сидят на generic-модели |
| Condition kinds | §8 минимум 10 типов | enum есть | Нет evaluators для `PLATFORM_CONDITION`, `AUTHENTICATION_CONDITION`, `RUNTIME_CONDITION`, `VALIDATION` (есть `Validation`, но kind в enum — отдельный) → всегда UNKNOWN |
| Data origins | §15: EXTERNAL_UNTRUSTED/AUTHENTICATED, CONFIGURATION, DATABASE, INTERNAL_SERVICE, CONSTANT, GENERATED | enum есть; provenance покрывает http.Request/os.Args/net/config/generated + `populateOrigin` (Scan/Unmarshal out-params), DB-драйверы по pkg path, gRPC-стабы и http-клиенты с config-endpoint → INTERNAL_SERVICE (`16`) | `EXTERNAL_AUTHENTICATED` не различается; детекция драйверов по pkg path — эвристика, кастомные обёртки не покрыты |
| Transformations | §15: `source → transformations → validation → sink`, security-relevant transforms | `TraceArgument` даёт origin конечного аргумента | Цепочка трансформаций не моделируется: `quote()/escape()/cast()` между source и sink не учитываются в reasoning |
| Negative check | §19: callers, **interface implementations**, runtime registration, **build-tagged code**, configuration overrides, alternate entrypoints | func_value/linkname/reflect/unsafe/plugin по scoped rules | interface-impl и build-tag покрыты (`GatedRefs`/`InterfaceDispatchSites`); `configuration overrides` как NV-концепт нет — `config_flag`/`config_key` читают knob'ы условий, но не конфигурацию, меняющую reachability |
| Typed tools | §17: 17 инструментов | реализовано 7: read_function, find_symbol, find_callers, find_entrypoints, trace_argument, find_validations, scan_dynamic | Нет: `get_vulnerability`, `get_advisory`, `get_fix_references`, `get_fix_diff`, `get_module_version`, `get_dependency_graph`, `run_govulncheck`, `read_source`, `search_source`, `run_build`, `run_tests` — LLM-агент не может сам получить advisory/diff/версии или запустить сборку/тесты |
| Hypothesis loop | §18 + agent §6,§16: OPEN→CONFIRMED/REJECTED, gap-driven planner | `Hypothesis` тип есть в domain | **Не инстанцируется нигде** — нет цикла select UNKNOWN → hypothesis → tool → claim → gap analysis; есть только однопроходный evaluate + fallback evaluator |
| Persistence | §22: hypotheses, tool_executions с version/input/cmd/exit/stdout/stderr/hash | кейс + raw govulncheck в evidence.Content + `EvidenceGraph.ToolExecutions` (tool, version, args, exit, sha256 обоих потоков, ms) через ctx-рекордер; `Evidence.ToolVersion` заполнен для govulncheck | `EvidenceGraph.Runtime` не заполняется; env прогонов не пишется (секреты); reproducibility-diff хэшей между прогонами не делается |
| Reviewer | §21: root cause, missed conditions, patch misinterpretation, scope mismatch, contradictions | Structural проверяет: TRUE без evidence, FALSE без NV, dangling refs, model без root cause | Не проверяются: пропущенные mandatory conditions (если LLM выкинул условие — не поймаем), «patch misinterpretation», «scope mismatch» |

## 3. Отсутствует концептуально — сканер обязан, но не делает

### 3.1 Deployment/exposure как факт, не caveat — `done` (первый слой)

Реализовано по `11-exposure-facts-plan.md`: `runExposure` в
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

Реализовано по `10-pattern-library-plan.md`: классификатор (CWE →
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
generic-модели — паттерны добавляются по мере живых кейсов; `bound` —
текстовая аннотация, доказательство гарды не реализовано.

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

`Index.GatedRefs` (по `12-negative-coverage-plan.md`) сканирует
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

### 3.5 Multi-hop provenance через vendor internals

`TraceArgument` ограничен 2 caller hops и продуктовым кодом. Для vulns
вида «peer → library internals → sink» аргумент sink'а живёт внутри
vendor-кода — provenance туда не заходит (закрыто эвристикой
unexported+peer-driven, но не настоящим trace).

### 3.6 run_build / run_tests evidence

Спека §17 предполагает сборку и тесты как evidence source —
определяет, компилируется ли путь вообще, существует ли тест,
файлится ли продукт. Сейчас таких evidence нет; при build failure
govulncheck-адаптер просто отдаёт tool limitation.

### 3.7 Метрики / eval harness — `done` (первый слой)

Спека §9 плана: root-cause accuracy, FALSE precision, **false-safe
count** (стоп-критерий), INCONCLUSIVE rate, evidence reproducibility.

Реализовано (`14-eval-harness-plan.md`): `internal/eval` + сабкоманда
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
resolved version. CycloneDX — не реализовано.

### 3.9 Remediation workflow

§24 скетч: worktree → `go get` → build/tests → повторный анализ.
Намеренно отложено (D15), но в архитектуру заложено; реализовано
только текст remediation в отчёте.

### 3.10 Intake из tracker

Только CLI `--vuln`/`--vuln-file`. Generic tracker-адаптер (GitHub
Issues/Jira) — deferred by design.

## 4. Приоритет (по принципу «какой UNKNOWN закрывает»)

1. ~~Pattern library~~ — `done` (базовый слой, §3.2).
2. ~~Deployment facts (bind/endpoint)~~ — `done` (первый слой, §3.1);
   auth на entrypoint'ах — в резерве.
3. ~~Configuration reading~~ — `done` (первый слой): `check=config_flag`
   резолвит code-knob'ы (`FieldAssignments` + zero-value для bool),
   `check=config_key` — ключи в конфигах репо; `C-TLS-VERIFY` supporting
   в peer-driven. Live: InsecureSkipVerify=TRUE найден на
   продукт-референс.
4. ~~Interface-impl + build-tag paths в negative check~~ — `done`:
   `GatedRefs` + `InterfaceDispatchSites` деградируют VERIFIED в
   INSUFFICIENT_SCOPE при находках вне typed-скоупа.
5. ~~DATABASE/INTERNAL_SERVICE origins~~ — `done` (первый слой, §таблица
   origins; `16-data-origins-plan.md`); authenticated-vs-trusted — отдельно.
6. **Недостающие 10 typed tools** — нужны полноценному hypothesis loop.
7. **Hypothesis/gap-analysis loop** — каркас, который все это связывает.
8. ~~Eval harness + false-safe metric~~ — `done` (первый слой, §3.7);
   далее — живой корпус и ground-truth метрики.
9. ~~tool_executions/ToolVersion~~ — `done` (первый слой, §таблица
   Persistence; `17-tool-audit-plan.md`). Остаток: `Runtime` evidence,
   reproducibility-diff.
10. ~~VEX-экспорт~~ — `done` (OpenVEX, §3.8); CycloneDX — при нужде.
