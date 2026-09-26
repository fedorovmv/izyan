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
| NEGATIVE_CHECK | `goanalysis.Verifier` | FALSE-кандидат → VERIFIED/CONTRADICTED/INSUFFICIENT_SCOPE |
| REVIEW | Structural + LLM reviewer | findings → bounded repair (только демоция в UNKNOWN) |
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
что по инварианту отличается от «не эксплуатируется».

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

**Fallback при `not_in_db`** (reachability без govulncheck):

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
| `SymbolReachable` | `SYMBOL_REACHABLE` | govulncheck-трейсы → TRUE; `not_in_db` → module-usage fallback; covered+нет пути → FALSE-кандидат. Param-ветки: `direction=read` → product-refs из `SymbolRefs` (INFO_LEAK); `sequence=a->b` → все члены пары вызваны (URI_CONFUSION) |
| `ServerTransportInput` | `ATTACKER_CONTROL`, `INPUT_CONSTRAINT` | server-фреймы уязвимого модуля в трейсе + listener-entrypoints → TRUE; client-side: module usage + unexported subjects + peer-input → TRUE (`input_source=peer` в params или remote-input в тексте); `input_source=arg/config` — сразу `ArgumentOrigin` |
| `ArgumentOrigin` | `ATTACKER_CONTROL` | `DataFlows`: external origin → TRUE; все non-external → FALSE-кандидат |
| `Validation` | `INPUT_CONSTRAINT` | `FindValidations` — guard-выражения до sink |
| `Presence` | `check=symbol_present` | `SymbolDecls`: subject объявлен в dep source → TRUE; проверен и отсутствует → FALSE-кандидат (INFO_LEAK) |
| `VersionFact` | `BUILD_CONDITION`, `CONFIGURATION` | semver-сравнение («prior to X.Y.Z», «нет в vulnerable versions») по `AffectedResult` |

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

VERIFIED FALSE → можно опираться; CONTRADICTED → UNKNOWN;
INSUFFICIENT_SCOPE → UNKNOWN, вердикт не может использовать FALSE.

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

## 11. Чего не хватает (известные границы)

- `ModuleInternalReach` работает по vendored-исходникам; без `vendor/`
  внутримодульные цепочки не проверяются → UNKNOWN вместо FALSE.
- `INPUT_CONSTRAINT` на формат данных («поле длиннее X») пока резолвится
  только по remote-input эвристике, не по реальным границам парсера.
- Deployment-факты (кто может достучаться до listener'а/endpoint'а)
  фиксируются caveat'ом, не резолвятся — следующий шаг: читать bind-
  адрес из конфига/манифестов.
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
