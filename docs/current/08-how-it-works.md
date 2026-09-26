# Как работает анализатор: пайплайн, источники истины, особенности govulncheck

Описание реализованного алгоритма по состоянию кода. При расхождении со
спекой код — истина; спека `01-governing-spec.md` — цель.

## 1. Что программа отвечает

Не «достижима ли уязвимая функция» (это один сенсор), а «выполняются ли
обязательные условия эксплуатации данной advisory на данном snapshot».
Инвариант, от которого всё следует:

> Отсутствие найденного пути — не доказательство отсутствия пути.
> «Не знаю» — легитимный ответ; «безопасно» — только после проверки.

## 2. Конвейер состояний

```
CREATED → SNAPSHOT_PRODUCT → RESOLVE_VULNERABILITY → CHECK_AFFECTED
  → RESOLVE_ROOT_CAUSE → BUILD_EXPLOIT_MODEL → COLLECT_EVIDENCE
  → EVALUATE_CONDITIONS → NEGATIVE_CHECK → REVIEW
    ↕ REVISE → REPAIR_ANALYSIS → REVIEW (bounded: MaxReviewIterations)
  → EVALUATE_VERDICT → BUILD_REPORT → COMPLETED
```

Состояние кейса (`AnalysisCase`) пишется на диск после каждого перехода —
прогон restartable и не зависит от LLM-истории.

### Что делает каждая стадия

| Стадия | Источник истины | Выход |
|---|---|---|
| SNAPSHOT_PRODUCT | `go version`, `go.mod` (`GoModDirective`), флаги | `ProductSnapshot` — toolchain, GOOS/GOARCH, `--release-go-version`, `--binary` |
| RESOLVE_VULNERABILITY | OSV API / `--vuln-file` | `Vulnerability` + алиас-дотягивание GO-* документа, если у GHSA нет `ecosystem_specific.imports` |
| CHECK_AFFECTED | `go list -m all` + `vendor/modules.txt`, `go list -deps ./...`, `x/mod/semver` | `AffectedResult`: module/version/package/build — каждый факт с evidence |
| RESOLVE_ROOT_CAUSE | advisory `affected_symbols` → fix-commit diff → LLM-retry | верифицированные sink-символы (каждый проверен `FindSymbol` в dep source) |
| BUILD_EXPLOIT_MODEL | `Classify` (CWE → keywords → fix-diff) → pattern из `exploit.Registry` → LLM (при наличии) → generic fallback | `ExploitModel` — класс + mandatory conditions с `Subjects`/`Params` |
| COLLECT_EVIDENCE | govulncheck + `goanalysis.Index` | `EvidenceGraph`: call paths, data flows, entrypoints, module usages, limitations |
| EVALUATE_CONDITIONS | evaluators chain | `Claim{TRUE/FALSE/UNKNOWN}` per condition |
| GAP_ANALYSIS | hypothesis loop: `TraceArgumentBound`, `ScanDynamic`, `InterfaceDispatchSites`+`GatedRefs` | `Hypothesis` OPEN→CONFIRMED/REJECTED/UNRESOLVED; новые flows → re-evaluate |
| NEGATIVE_CHECK | `goanalysis.Verifier` | FALSE-кандидат → VERIFIED/CONTRADICTED/INSUFFICIENT_SCOPE |
| REVIEW | Structural + LLM reviewer | findings → bounded repair (только демоция в UNKNOWN) |
| REPAIR_ANALYSIS | demotion-only repair по high-severity findings | только понижает claim до UNKNOWN → re-REVIEW |
| EVALUATE_VERDICT | `VerdictEvaluator` | вердикт |
| BUILD_REPORT | — | `report.{json,md}` + `tracker_comment.md` |

## 3. Verdict-матрица

| Вердикт | Условие |
|---|---|
| `NOT_AFFECTED` | FALSE в affected-цепочке (модуль/версия/пакет/build) |
| `EXPLOITABLE` | все mandatory conditions TRUE |
| `NO_EXPLOIT_PATH_FOUND` | хотя бы один mandatory FALSE **и** negative check VERIFIED |
| `INCONCLUSIVE` | всё остальное, включая FALSE без верификации |

`INCONCLUSIVE` — нормальный ответ, а не ошибка: «доказать не удалось»,
что по инварианту отличается от «не эксплуатируется». Каждый такой
вердикт несёт список `Hypotheses` — что пытались проверить и почему не
получилось (CONFIRMED-гипотеза о dynamic dispatch — документированная
потеря покрытия, а не тихий UNKNOWN).

### Gap-analysis loop

`GAP_ANALYSIS` — bounded цикл по UNKNOWN mandatory claim'ам:
планировщик генерирует гипотезу (например «origin резолвится глубже
caller-chain»), tool-экшн собирает evidence, claim переоценивается;
до фикспоинта (≤3 итераций) или `MaxToolCalls`. Экшены детерминистичны:
углублённый трейс аргумента (hops=6 вместо 2), `ScanDynamic` при нуле
call-sites, `InterfaceDispatchSites`/`GatedRefs` для скрытой
достижимости, `FindValidationsBound` для VALIDATION — подъём по
caller-chain и поиск гард на аргументе. Гарда засчитывается как
покрывающая sink (`Validation.Covers`) только когда **все** caller-ветки
guard'ят; частичное покрытие — informational evidence, claim остаётся
UNKNOWN. Экшены, документирующие потерю покрытия, никогда не
двигают claim в FALSE — они объясняют честный UNKNOWN.

## 4. Роль govulncheck — что он умеет и чего не умеет

### Что делает

`-mode source ./...` строит call graph по коду продукта и находит трейсы
от product entry points до уязвимых символов зависимости. Это единственный
готовый оракул достижимости; его finding-трейсы — authoritative evidence.

### Ограничения (все наблюдались на живых прогонах)

1. **Только своя БД.** Сканирует advisories из vulndb (GO-* записи).
   Нет режима «проверь advisory X» и нет `-mode query` — спросить
   «знаешь ли ты GHSA-…» нельзя. Молчание структурно неотличимо:
   «нет в БД» vs «есть в БД, но пути нет» vs «версия не аффектнута».
2. **Статический call graph.** reflect/plugin/`go:linkname`/func-values
   не моделируются — «нет трейса» ≠ «не достижим».
3. **Символный формат.** Трейс идёт до символов, объявленных в
   advisory (`ecosystem_specific.imports`), которые могут не совпадать
   с теми, что мы вывели из fix-commit'а. Несовпадение множеств =
   ложный «нет пути».
4. **Не знает семантику.** «Достижим» не говорит, под каким входом и
   при какой конфигурации — peer-controlled сетевой ввод, аргумент из
   кода и константа для него одно и то же.
5. **Toolchain.** `-mode source` использует локальный Go; реальный
   toolchain релиза виден только в `-mode binary` (читается из
   встроенного build info). Мы поддерживаем `--binary` и
   `--release-go-version`.

### Как мы компенсируем

**`GovulncheckCoverage`** — записано в кейсе явно:

- `"covered"` — advisory (по ID или GO-* алиасу) подтверждённо в БД:
  либо стрим выдал `osv`/`finding` сообщения, либо `dbKnowsAdvisory`
  нашёл GO-* запись через OSV query по модулю. Тогда ноль findings —
  легитимный FALSE-кандидат (см. ниже).
- `"not_in_db"` — ни стрим, ни vulndb-листинг не знают advisory.
  Молчание ≠ данные; limitation в отчёте + timestamp снапшота БД vs
  `advisory modified` (видно, когда advisory просто новее БД).

**Мэтчинг трейсов.** `reachabilitySubjects` = union(root-cause symbols,
advisory `affected_symbols`); `CallSite` хранит receiver, matching
понимает `Type.Method` ↔ `*T M`. OSVSource при пустых symbols
дотягивает GO-* алиас-документы (у GHSA symbols часто нет).

**Fallback без govulncheck.** Когда govulncheck не смог оценить advisory —
`not_in_db` **или бинарь вообще не запустился** — reachability решается по
module-usage evidence (`libraryUsageVerdict`). Отказ инструмента не
фабрикует ни FALSE (требуется маркер «usage scan ran»), ни потерю
позитивного evidence: прямой вызов sink из продукта → TRUE с limitation.

| Случай | Результат |
|---|---|
| все subjects unexported + продукт дёргает API модуля | TRUE — internals исполняются в peer-driven пути библиотеки |
| exported subject: есть vendor-цепочка `product-API → sink` или прямой вызов | TRUE по `ModuleInternalReach`/`Callee` |
| exported subjects: проверено — цепочек нет | FALSE-кандидат |
| проверка не выполнялась | UNKNOWN |

`ModuleUsage` собирает product call sites в API модуля с точным callee
(`pkg.Recv.Method`). `ModuleInternalReach` загружает vendored-пакет
`packages.Load` (с типами), строит внутримодульный call graph и BFS'ит
от используемых API до sink — реальные цепочки вроде
`DialTLS → DialConfig → Open → Connection.reader → ReadFrame → parseMethodFrame → readLongstr`
записываются в evidence.

## 5. Pattern library — класс-специфичные exploit models

`BUILD_EXPLOIT_MODEL` больше не сводится к generic-паре `C-REACH`+`C-INPUT`:

1. `Classify` (`internal/exploit/classify.go`) выбирает `Class`:
   CWE-маппинг → keyword-регексы по summary/description → keywords по
   уже собранному fix-diff (без новых tool calls) → `UNKNOWN`. Класс
   и источник классификации фиксируются (`ExploitModel.Class`, для
   keyword/patch-инференса — limitation).
2. `Registry` (`internal/exploit/patterns.go`) держит декларативные
   `Pattern` — набор `ConditionTmpl` (что проверять, не чему равно) +
   `SkipGenericReach/Input`. Шаблоны несут `Params`:
   `input_source=peer|arg|config`, `direction=read`, `sequence=a->b`,
   `bound=…`, `check=symbol_present`.
3. `Instantiate` привязывает шаблоны к subject-пулам по `Bind`-оси:
   `BindSinks` (root-cause sinks), `BindDatums` (чувствительные данные),
   `BindPair` (API-пара round-trip). `ExportedOnly`/`MinSubjects`
   применяются к выбранному пулу; неполный пул → limitation, условие
   остаётся непривязанным — никогда не деградирует в bind на sinks.
   Непокрытые generic-роли домердживаются — `C-REACH`/`C-INPUT` остаются
   fallback'ом всегда.
4. Пулы `Datums`/`Pairs` собираются до instantiate и верифицируются
   `FindSymbol` в dep source:
   - advisory-символы формы `Type.Field` и bare-имена, резолвящиеся в
     struct-типы (`IsStruct`);
   - `SensitiveFields(pkg)` — детерминистичный скан struct-полей dep
     package по credential-именам (password|secret|token|sasl|…);
   - pair-completion по stem-таблице (`String→Parse{T}`, `Marshal→
     Unmarshal{T}`, …) — `URI.String` достраивается `ParseURI`;
   - LLM-предложения (`datum_symbols`/`pair_symbols` в схеме exploit-
     модели) — только символы внутри advisory-модуля, только после
     FindSymbol-верификации.
5. LLM-условия дополняют модель; пустые pattern-параметры (`bound`)
   заполняются из LLM, непустые — не перезаписываются.

Собранные классы:

| Класс | Mandatory | Supporting |
|---|---|---|
| peer-driven (`WIRE_PARSER`, `OOB_WRITE`, `INTEGER_OVERFLOW`, `RESOURCE_EXHAUSTION`) | `C-REACH`, `C-PEER-INPUT`, `C-CONSTRAINT` (`input_source=peer`, `bound`) | `C-ENTRY` |
| `INFO_LEAK` | `C-DATA-PRESENT` (`check=symbol_present`), `C-EXPOSED` (`direction=read`) — оба `BindDatums`; generic-условия выключены | `C-USE` |
| `URI_CONFUSION`, `CONFIG_INJECTION` | `C-ROUNDTRIP` (`sequence=`, `BindPair`), `C-INPUT` | — |
| `NIL_DEREF` | `C-REACH`, `C-TRIGGER` | `C-HOT-PATH` |

`UNKNOWN`/непокрытые классы → прежняя generic-модель. `bound` — текстовая
аннотация: семантическое доказательство гарды осознанно отложено.

Params задают и сбор evidence, и evaluation: `check=symbol_present` →
`collectPresence` (`SymbolDecls` через `FindSymbol`, который умеет
резолвить поля структур); `direction=read` → `collectReaders`
(`SymbolRefs` через `SearchSymbol` — `Type.Field` селекторы и
composite-literal ключи матчатся по declaring struct); `sequence=` →
сверка членов пары с module-usage/`ModuleReachable`; `input_source` →
выбор ветки в `ServerTransportInput`.

## 6. Evaluators (condition → claim)

| Evaluator | Обрабатывает | Логика |
|---|---|---|
| `SymbolReachable` | `SYMBOL_REACHABLE` | govulncheck-трейсы → TRUE; `not_in_db` или govulncheck не запустился → module-usage fallback; covered+нет пути → FALSE-кандидат. Param-ветки: `direction=read` → product-refs из `SymbolRefs` (INFO_LEAK); `sequence=a->b` → все члены пары вызваны (URI_CONFUSION) |
| `ServerTransportInput` | `ATTACKER_CONTROL`, `INPUT_CONSTRAINT` | server-фреймы уязвимого модуля в трейсе + listener-entrypoints → TRUE; client-side: module usage + unexported subjects + peer-input → TRUE (`input_source=peer` в params или remote-input в тексте); `input_source=arg/config` — сразу `ArgumentOrigin` |
| `ArgumentOrigin` | `ATTACKER_CONTROL` | `DataFlows`: external origin → TRUE; все non-external → FALSE-кандидат |
| `Validation` | `INPUT_CONSTRAINT` | `FindValidations` — guard-выражения до sink |
| `Presence` | `check=symbol_present` | `SymbolDecls`: subject объявлен в dep source → TRUE; проверен и отсутствует → FALSE-кандидат (INFO_LEAK) |
| `Exposure` | `check=exposure` | `Exposures`: факты есть → TRUE (перечисление + scope, caveat'ы в limitations); фактов нет или скан не запускался → UNKNOWN — FALSE не выдаётся никогда: отсутствие listener/dial-сайта в коде не доказывает недостижимость (proxy/ingress вне кода) |
| `ConfigFlag` | `check=config_flag` / `config_key` | code-knob: присваивания `Type.Field` из `ConfigFlags` (literal/const резолв) — insecure → TRUE, все safe → FALSE-кандидат; никогда не присвоен + тип bool + insecure≠zero → FALSE-кандидат по Go zero-value; file-key: `Configuration` items из `FindKey` |
| `VersionFact` | `BUILD_CONDITION`, `CONFIGURATION` | semver-сравнение («prior to X.Y.Z», «нет в vulnerable versions») по `AffectedResult` |

**Configuration checks** (`C-TLS-VERIFY` supporting в peer-driven
паттерне — `crypto/tls Config.InsecureSkipVerify`, insecure=true; LLM
может предлагать свои knob'ы через params — верифицируются `FindSymbol`):

- `FieldAssignments` собирает composite-literal ключи и `x.Field = v`
  присваивания; значение резолвится через `types.Info` (literal/const).
- `SymbolFieldType` даёт kind поля → zero-value семантика Go
  детерминистична: bool-knob без присваиваний = false.
- `exposure.FindKey` — поиск произвольного ключа в конфигах репо
  (та же walk+sanitize, что ScanRepo, без addr-фильтра).
- Живой результат: продукт-референс ставит `InsecureSkipVerify=true`
  в `pkg/tls/type.go` → `C-TLS-VERIFY` TRUE — факт «peer on the wire»
  для всех peer-driven кейсов подтверждён конфигурацией.

**Exposure facts** (`C-EXPOSURE`, supporting в peer-driven и NIL_DEREF
паттернах — не гейтит вердикт, но получает claim и попадает в отчёт):

- `ListenSites` — inbound surface: `net.Listen*`, `http.Server{Addr}`,
  `grpc.NewServer`/`Serve`. Аргумент адреса резолвится через literal/
  const/var/field/`os.Getenv`; server-shape вызовы (`srv.Serve(lis)`)
  трассируют receiver до определяющего вызова в той же функции.
- `DialSites` — outbound в уязвимый модуль (`amqp.Dial`, `grpc.Dial`…,
  имя по `dialNameRe`, пакет по префиксу advisory-модуля).
- `ExposureFact{Address, AddressSource, Scope}`: source = `literal`/
  `const`/`var:`/`field:`/`env:`/`config:`; scope = `static`/`configured`/
  `unknown` (`OutboundScope`: var/field/env/config → configured).
- `env:`-адреса дозрезолвляются через `exposure.ScanRepo` — walk
  yaml/env/toml/json конфигов репозитория по `(listen|bind|addr|host|
  port|dsn|url|endpoint)`-ключам.
- `_test.go`-файлы исключаются — тестовый код не deployed surface.
- Claim несёт caveat «endpoint операторски конфигурируем» — доверие
  настроенному сервису остаётся deployment-решением, факт лишь показывает
  где поверхность.

TRUE-claim обязан нести evidence ID — структурный ревьюер иначе
демотирует (provenance-инвариант).

## 7. Negative verification — защита FALSE

FALSE-кандидат проходит `Verifier` до того, как вердикт на него опирается:

- `SearchSymbol` — есть ли ещё ссылки на subject в продукте.
- `ScanDynamic` — `func_value`/`linkname`, целящий сам subject →
  CONTRADICTED → demote в UNKNOWN. `linkname` контрадиктит только
  если в detail упомянут subject (чужая прагма — игнорируется).
- `reflect`/`unsafe`/`plugin` — ослабляют FALSE **только для exported
  subjects**: unexported-символ рефлексией извне не достать, `unsafe`
  сам по себе ничего не вызывает (значим через func_value/linkname,
  которые проверяются адресно).
- Для `ATTACKER_CONTROL` — provenance всех call sites.
- `direction=read` — любая product-ссылка на subject это читатель →
  CONTRADICTED.
- `sequence=` — проверяются только **не вызванные** члены пары: ссылки
  на них → INSUFFICIENT_SCOPE, нет → VERIFIED.
- Параметрические check-условия (`config_flag`/`config_key`/`exposure`/
  `symbol_present`) NV не проверяет subject-escape правилами — их FALSE
  фальсифицируется собственным evidence; вердикт — INSUFFICIENT_SCOPE.
- **Scope-расширение** (после VERIFIED любой стратегией —
  `extendNegativeScope`): `GatedRefs` ищет ссылки на subject в файлах,
  исключённых текущими build tags (`pkg.IgnoredFiles`, без `_test.go`),
  синтаксически по импорту пакета; `InterfaceDispatchSites` ищет вызовы
  `x.Method()` по интерфейсному типу, который реализует тип субъекта
  (`types.Implements`). Находки → `INSUFFICIENT_SCOPE` (не CONTRADICTED:
  tag-файл может быть мёртвым кодом, interface-dispatch не доказывает
  конкретный impl) — FALSE остаётся, но вердикт/ревьюер на него не
  опираются.

VERIFIED FALSE → можно опираться; CONTRADICTED → claim демотируется в
UNKNOWN; INSUFFICIENT_SCOPE → claim остаётся FALSE, но вердикт на него
не опирается и ревьюер фиксирует medium-finding.

## 8. Review + repair

`review.Structural` (детерминистический) + `llm.Reviewer` (если включён)
→ merged findings. REVISE → bounded repair: демоция неподдержанных
claim'ов в UNKNOWN, бюджет `MaxReviewIterations`. Правила защиты:

- TRUE-claim от детерминистического evaluator'а (`Producer` =
  `evaluator.*`) с deterministic/authoritative evidence **не демотируется**
  — concern ревьюера записывается как caveat (LLM-ревьюер реально ловили
  на демоции валидного govulncheck-трейса).
- FALSE-claim демотируется всегда при найденных ограничениях — negative
  evidence по природе слабее.
- Structural демотирует FALSE при «widens the call graph»-limitation —
  детерминистично, не дожидаясь LLM.

## 9. Go toolchain — три уровня

| Источник | Когда | Что даёт |
|---|---|---|
| `--release-go-version` | версия из тикета/релиз-ноты | authoritative для stdlib-advisory |
| `--binary` + `go version -m` | собранный артефакт | реальный toolchain + модули дистрибутива; `govulncheck -mode binary` |
| локальный `go version` | fallback | + limitation «toolchain релиза может отличаться» |

`go.mod` (`GoModDirective`) — **нижняя граница**, не факт сборки; для
stdlib-advisory записывается явный limitation.

## 10. LLM-слой — строго поверх детерминистики

- LLM предлагает структуры: root-cause кандидаты, exploit-model
  conditions, review findings. Всё проходит детерминистическую
  верификацию до влияния на вердикт.
- Отказ/ошибка LLM → fallback на детерминистический путь + limitation
  в отчёте (видно в прогонах: `llm exploit model failed` → кейс всё
  равно дошёл до вердикта).
- `--deterministic-only` гасит слой полностью.
- LLM-агент работает через 17 typed tools (§17,
  `internal/llm/tools.go`): advisory/фикс-документы, module graph,
  govulncheck, source read/search, exec-инструменты. Каждый вызов
  ограничен `MaxToolCalls`, результат — evidence в графе; tool miss —
  ошибка модели, не «фактов нет». `run_build`/`run_tests` исполняют код
  репозитория и требуют явного `--allow-exec`; вызовы проходят через
  toolaudit и видны в `tool_executions`.

## 11. Eval harness — регрессионный корпус

`vuln-analyzer eval --corpus eval/corpus.json` прогоняет кейсы через
полный пайплайн и считает метрики из спеки §9. Корпус — JSON:
`cases[]` с `vuln`/`vuln_file`, `repo`, `root_causes`, `expect`
(допустимые вердикты — диапазон легитимен, INCONCLUSIVE часто правильный
ответ) и `expect_claims` (per-condition утверждения).

| Метрика | Смысл |
|---|---|
| `false_safe` | safe-вердикт при недопускающем его ожидании — стоп-критерий, должен быть 0 |
| `expect_pass/fail` | вердикт в/вне допустимого списка |
| `claims_fail` | claim-ассерты не сошлись — регрессия внутри вердикта |
| `inconclusive` | доля неопределённости (распределение, не провал) |
| `errors` | кейсы, завершившиеся ошибкой пайплайна |

Exit code 1 при любом false-safe/expect-fail/claims-fail/error —
пригодно для CI. `--out`/`--json` пишут markdown/JSON-отчёт; case-state
по умолчанию уходит в temp dir (`--case-dir` для отладки падения).
Регрессионный прогон **детерминистичен**: eval по умолчанию работает в
`--deterministic-only` режиме, `--with-llm` — opt-in для замера
LLM-варианта (LLM-предложения недетерминированы и ломают
воспроизводимость corpus-метрик).
Пути в корпусе — относительно файла корпуса. Синтетические advisory
`eval/advisories/` покрывают механизмы фикстур `testdata/`; живой корпус
на реальных GHSA — следующий слой (`09-gap-analysis` §3.7).

## 12. Target Go toolchain

Релизный бинарь собран конкретной версией Go — для `std`/`toolchain`/`cmd`
адвизори анализ обязан резолвить исходники **той** версии, а не локальной:

- Версия берётся по цепочке: build info бинаря (`--binary`) →
  `--release-go-version` → `corpus.go_version` (eval). Пусто → local.
- `internal/toolchain.Resolve`: local-match → `~/sdk/go<ver>` (dl SDK,
  оффлайн) → `GOTOOLCHAIN=go<ver>` (Go ≥1.21 скачивает в module cache).
  Недоступно → `Mismatch` + limitation; молчаливого чужого GOROOT нет.
- `Toolchain.Env` (PATH/GOTOOLCHAIN) протягивается во все subprocess'ы
  (`ExecGoTool`, `ExecRunner`) и `packages.Load` через `Index.Env` —
  stdlib-символы резолвятся под целевым GOROOT.
- Кейс фиксирует `analysis toolchain: go<ver> (<mode>)` в limitations.
- Docker — режим запуска, не toolchain: `eval/Dockerfile` собирает
  `golang:<target>` + бинарь анализатора; внутри `go` и есть целевая
  версия (toolchain сборки анализатора роли не играет).
- Важная граница: toolchain старше `go`-директивы модуля не загружает
  репо → честный `INCONCLUSIVE`, а не анализ по другой версии.

## 12a. Tool execution audit

Каждый внешний вызов инструмента пишется в
`EvidenceGraph.ToolExecutions` (спека §22): tool, version, dir, args,
exit_code (-1 = не стартовал/ctx kill), sha256 stdout+stderr,
duration_ms, error. Реализация — `internal/toolaudit`: рекордер
ездит в ctx (`WithRecorder` в `analyzeCase` сразу после создания кейса),
поэтому shared-обёртки из scan/eval (кэшированные runner'ы, созданные
до кейса) атрибутируют прогоны правильному кейсу. Все exec-точки —
`repository` (git, go version[-m]), `affected.runGo` (go list),
`goanalysis.ExecRunner` (govulncheck, `-version`), toolchain-пробы —
проходят через `toolaudit.Run`. Большие выводы не дублируются: хэш
привязывает запись к evidence.Content. Отчёт показывает таблицу
«Tool executions». `Evidence.ToolVersion` заполнен для govulncheck
(вывод `-version`/vulndb-строки). Не записываются: `packages.Load`
(in-process), env прогонов (секреты).

## 12b. OpenVEX-экспорт

Рядом с `report.{json,md}` каждый кейс пишет `openvex.json`
(`internal/report.OpenVEX`, openvex.dev/ns/v0.2.0). Маппинг вердиктов:

| Вердикт | VEX status | justification |
|---|---|---|
| EXPLOITABLE | affected | — (impact = reason) |
| NOT_AFFECTED | not_affected | `component_not_present` (модуль/билд) или `vulnerable_code_not_present` (версия/пакет) |
| NO_EXPLOIT_PATH_FOUND | not_affected | `vulnerable_code_not_in_execute_path` — только после прошедшей negative-верификации |
| INCONCLUSIVE | under_investigation | action_statement = reason |

Продукт — `pkg:golang/<module>@<analyzed commit>`; уязвимая зависимость —
subcomponent `pkg:golang/<module>@<resolved_version>`. CycloneDX не
экспортируется.

## 13. Чего не хватает (известные границы)

- `ModuleInternalReach` работает по vendored-исходникам; без `vendor/`
  внутримодульные цепочки не проверяются → UNKNOWN вместо FALSE.
- `INPUT_CONSTRAINT` на формат данных («поле длиннее X») пока резолвится
  только по remote-input эвристике, не по реальным границам парсера.
- Deployment-факты резолвятся частично: listener/dial-сайты и
  provenance адреса собираются (`C-EXPOSURE`), но остаются supporting-
  уточнением, не гейтом; auth на entrypoint'ах, k8s/docker-манифесты и
  связывание var→config-значений без `env:`-источника не покрыты.
- NV-скоуп расширен (tag-excluded файлы + interface dispatch), но
  остаётся синтаксическим/типовым: компилируемость tag-варианта не
  проверяется, impl'ы интерфейса *внутри* dep-кода не перечисляются.
- gRPC-кейс (`GHSA-vp52`) проходит до `EXPLOITABLE`; RabbitMQ —
  4 EXPLOITABLE (unexported sinks + module usage + vendor-цепочки).
  Два бывших INCONCLUSIVE моделируются паттернами: credential retention
  → `INFO_LEAK` (`C-DATA-PRESENT` TRUE на реальных полях
  `PlainAuth.Password`/`Config.SASL`/`AMQPlainAuth.Password` из
  field-scan'а + `C-EXPOSED` VERIFIED FALSE), URI round-trip →
  `URI_CONFUSION` (`C-ROUNDTRIP` достроен stem'ом до `URI.String→
  ParseURI`, VERIFIED FALSE по паре). Оба FALSE демотируются ревьюером
  по `reflect`-маркеру → INCONCLUSIVE — корректно: `FieldByName`/
  `MethodByName` реально могут читать экспортируемые поля и вызывать
  экспортируемые методы, исключить их статически нельзя.
