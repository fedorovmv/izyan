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
| Data origins | §15: EXTERNAL_UNTRUSTED/AUTHENTICATED, CONFIGURATION, DATABASE, INTERNAL_SERVICE, CONSTANT, GENERATED | enum есть; provenance покрывает http.Request/os.Args/net, частично config/generated | `DATABASE`/`INTERNAL_SERVICE` не распознаются → UNKNOWN; `EXTERNAL_AUTHENTICATED` в enum, но классификация authenticated-vs-trusted не различается |
| Transformations | §15: `source → transformations → validation → sink`, security-relevant transforms | `TraceArgument` даёт origin конечного аргумента | Цепочка трансформаций не моделируется: `quote()/escape()/cast()` между source и sink не учитываются в reasoning |
| Negative check | §19: callers, **interface implementations**, runtime registration, **build-tagged code**, configuration overrides, alternate entrypoints | func_value/linkname/reflect/unsafe/plugin по scoped rules | interface-impl dispatch и build-tag-варианты не ищутся адресно; `configuration overrides` нет — конфигурация вообще не читается |
| Typed tools | §17: 17 инструментов | реализовано 7: read_function, find_symbol, find_callers, find_entrypoints, trace_argument, find_validations, scan_dynamic | Нет: `get_vulnerability`, `get_advisory`, `get_fix_references`, `get_fix_diff`, `get_module_version`, `get_dependency_graph`, `run_govulncheck`, `read_source`, `search_source`, `run_build`, `run_tests` — LLM-агент не может сам получить advisory/diff/версии или запустить сборку/тесты |
| Hypothesis loop | §18 + agent §6,§16: OPEN→CONFIRMED/REJECTED, gap-driven planner | `Hypothesis` тип есть в domain | **Не инстанцируется нигде** — нет цикла select UNKNOWN → hypothesis → tool → claim → gap analysis; есть только однопроходный evaluate + fallback evaluator |
| Persistence | §22: hypotheses, tool_executions с version/input/cmd/exit/stdout/stderr/hash | кейс + raw govulncheck в evidence.Content | `tool_executions` как отдельная сущность нет; `Evidence.ToolVersion` объявлен, но не заполняется; `EvidenceGraph.Runtime` не заполняется |
| Reviewer | §21: root cause, missed conditions, patch misinterpretation, scope mismatch, contradictions | Structural проверяет: TRUE без evidence, FALSE без NV, dangling refs, model без root cause | Не проверяются: пропущенные mandatory conditions (если LLM выкинул условие — не поймаем), «patch misinterpretation», «scope mismatch» |

## 3. Отсутствует концептуально — сканер обязан, но не делает

### 3.1 Deployment/exposure как факт, не caveat

Каждый EXPLOITABLE/peer-input TRUE сейчас несёт caveat «peer identity/exposure —
deployment property». Спека требует учитывать deployment configuration
(§12 agent spec). Что можно детерминистично читать:

- bind-адрес listener'а из конфига/кода (`0.0.0.0` vs `127.0.0.1` vs unix) —
  разделяет internet-vs-local экспозицию;
- endpoint'ы исходящих подключений из конфига/env — разделяет
  «внутренний брокер» vs «конфигурируемый внешний адрес»;
- auth middleware на entrypoint'ах.

Это единственный блокер между «EXPLOITABLE с оговоркой» и полным ответом.

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
  `C-PEER-INPUT`+`C-CONSTRAINT`+`C-ENTRY` вместо generic input;
- NIL_DEREF — `C-TRIGGER`+`C-HOT-PATH`.

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

### 3.3 Build/tag вариативность

`BuildRelevant` проверяет GOOS/GOARCH-ограничение пакета, но не ищет
альтернативные реализации под build tags (в spec negative-check явно
требует «build-tagged implementation»). Путь может существовать только
при `-tags foo` — проверки нет.

### 3.4 Interface-implementation paths

`func foo(x Interface)` — callee за x может быть любой impl. Negative
check ищет func_value/linkname, но не перечисляет implementations
интерфейса через `go/types` — а это стандартный путь обхода статического
«нет вызовов».

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

### 3.7 Метрики / eval harness

Спека §9 плана: root-cause accuracy, FALSE precision, **false-safe
count** (стоп-критерий), INCONCLUSIVE rate, evidence reproducibility.
Нет ни фикстур-корпуса сверх unit-тестов, ни подсчёта этих метрик на
реальном наборе advisory.

### 3.8 VEX/OpenVEX/CycloneDX экспорт

§25: «позднее OpenVEX/CycloneDX VEX». govulncheck сам умеет
`-format openvex`; наш verdict-модель в VEX-статусы мапится
(`EXPLOITABLE`→affected, `NO_EXPLOIT_PATH_FOUND`→not_affected+justification,
`INCONCLUSIVE`→under_investigation). Не реализовано.

### 3.9 Remediation workflow

§24 скетч: worktree → `go get` → build/tests → повторный анализ.
Намеренно отложено (D15), но в архитектуру заложено; реализовано
только текст remediation в отчёте.

### 3.10 Intake из tracker

Только CLI `--vuln`/`--vuln-file`. Generic tracker-адаптер (GitHub
Issues/Jira) — deferred by design.

## 4. Приоритет (по принципу «какой UNKNOWN закрывает»)

1. **Pattern library** — решает класс-специфичные mandatory conditions;
   снимает модельные INCONCLUSIVE (27gv/465g-подобные).
2. **Deployment facts (bind/endpoint/auth)** — конвертирует caveat в
   факт; единственный путь к уверенному вердикту для network-input vulns.
3. **Configuration reading** — CONFIGURATION-условия без него всегда
   UNKNOWN (VersionFact закрыл только версионные).
4. **Interface-impl + build-tag paths в negative check** — последние
   системные дыры в FALSE-верификации.
5. **DATABASE/INTERNAL_SERVICE origins** — расширяет ATTACKER_CONTROL
   для не-HTTP источников.
6. **Недостающие 10 typed tools** — нужны полноценному hypothesis loop.
7. **Hypothesis/gap-analysis loop** — каркас, который все это связывает.
8. **Eval harness + false-safe metric** — без неё регрессии неизмеримы.
9. **tool_executions/ToolVersion** — аудит-полнота, дёшево.
10. **VEX-экспорт** — интеграционная ценность, дёшево (openvex уже есть в govulncheck).
