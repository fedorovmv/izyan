# Live corpus — реальные advisory на реальном репо

## Real corpus — generated-manifest продукты (B13)

`eval/corpus-real.json` — 37 кейсов против реальных зависимостей через
generated-manifest продукты `eval/products/`: исходники коммитятся без
манифестов, `go.mod`/`go.sum` генерируются в `eval/.gen/<case-id>` из
полей `module`/`deps` кейса; кейс может задавать `goos`/`goarch`/
`build_tags` (нужно для platform-only dep'ов, напр. `unix.Faccessat` —
linux-only). Классы: yaml unmarshal DoS (v2 GO-2021-0061, v3
GO-2022-0603), markdown render (GO-2023-2074), go-getter arg-injection
(GO-2024-2800), ssh/x-crypto (GO-2022-0968 crash, GO-2024-3321 authz,
GO-2025-3487 slow-handshake DoS), jose2go (GO-2023-2409), jwt-go
missing-call (GO-2020-0017), http2 (GO-2023-2102), miekg/dns zone-parse
(GO-2020-0028), protobuf protojson unmarshal loop (GO-2024-2611), grpc
xDS RBAC bypass (GO-2026-6441), grpc xDS :authority panic — defect-locus
пул GO-2026-6443 на четырёх вариантах (mode-off / mode-on / wrapper /
pkg-present), x/sys Faccessat priv-report
(GO-2022-0493) — 12 классов, 11 реальных зависимостей.

Прогон: `analyzer eval --corpus eval/corpus-real.json` (сеть для `go mod
tidy` + govulncheck; `--mem-limit 4GiB` стоит по умолчанию).

Baseline-таблица govulncheck-vs-analyzer (последний прогон):

| case | analyzer | govulncheck | cleared? |
|---|---|---|---|
| real-yaml-http | EXPLOITABLE | reachable | нет — нужен эксплойт-review |
| real-yaml-file | INCONCLUSIVE | reachable | нет — unresolved |
| real-yaml-http-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-md-render | EXPLOITABLE | reachable | нет |
| real-getter-fetch | INCONCLUSIVE | reachable | нет |
| real-getter-const | INCONCLUSIVE | reachable | нет — protocol-switch через X-Terraform-Get держит GitGetter reachable; прежняя negative ground truth исправлена |
| real-ssh-server | EXPLOITABLE | reachable | нет |
| real-ssh-keyparse | INCONCLUSIVE | package-level | нет — sinks unexported; «zero product refs» вакуумен, dep-internal graph opaque |
| real-jose-decrypt | EXPLOITABLE | reachable | нет |
| real-jwt-auth | INCONCLUSIVE | package-level | нет — missing-call гейт: `VerifyAudience` мёртв, но sibling-пайплайн `MapClaims.Valid` жив → отсутствие вызова не доказывает безопасность |
| real-http2-server | NOT_AFFECTED | silent | **да — deterministic** |
| real-dns-zone | EXPLOITABLE | reachable | нет |
| real-getter-file | INCONCLUSIVE | reachable | нет — dispatch-key const `file`, eval-полнота не дожимает |
| real-getter-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-yaml-const | INCONCLUSIVE | reachable | нет — payload constant, но reflective value operations в ingress cone не доказаны безопасными |
| real-yaml3-http | EXPLOITABLE | reachable | нет |
| real-yaml3-const | INCONCLUSIVE | reachable | нет — payload constant, но reflective value operations в ingress cone не доказаны безопасными |
| real-protojson-http | EXPLOITABLE | reachable | нет |
| real-protojson-const | INCONCLUSIVE | reachable | нет — advisory symbols имеют scope KNOWN_ONLY; отдельного контракта полноты sink set нет, ingress содержит автономные и непроверенные источники |
| real-protojson-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-dns-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-dns-marshal | INCONCLUSIVE | package-level | нет — sinks частично unexported; та же vacuous-refs проблема |
| real-md-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-ssh-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-jose-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-ssh-callback | EXPLOITABLE | reachable | нет |
| real-micro-xds | INCONCLUSIVE | package-level | нет — dep-internal registry (`httpfilter.Register`) + watcher callbacks (B24) |
| real-micro-xds-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-micro-plain | NOT_AFFECTED | module-level | **да — rbac-пакет не в build graph; govulncheck также не сообщает уязвимый пакет** |
| real-micro-plain-6443 | EXPLOITABLE | reachable | нет — без basis весь declared set в L; HandleStreams в трейсе → `C-LOCUS` TRUE (машина не сужает L) |
| real-micro-plain-6443x | NO_EXPLOIT_PATH_FOUND | reachable | **да — locus-package-absent: expert `non_locus` на transport-символы → L={RouteAndProcess}, xds-пакет вне build graph (B30, spec §8)** |
| real-micro-xds-6443 | EXPLOITABLE | reachable | нет — xDS-режим включён, локус в govulncheck-трейсе |
| real-micro-wrap-6443 | EXPLOITABLE | reachable | нет — xDS через factory-обёртку; module-internal chain доказывает локус достижимым |
| real-micro-pkg-6443 | INCONCLUSIVE | reachable | нет — xds-пакет в build graph, но `RouteAndProcess` не вызывается; package-absence falsifier не применим, function-unreachability не доказана |
| real-unix-access | EXPLOITABLE | reachable | нет — `unix.Access` вызван на dep-пути, payload внешний |
| real-unix-stat | NO_EXPLOIT_PATH_FOUND | package-level | **да — zero-refs + dep-internal caller `unix.Access` транзитивно мёртв (нет product refs, нет caller'ов в модуле, сторонних импортеров пакета нет)** |
| real-unix-fixed | NOT_AFFECTED | silent | **да — deterministic** |
| real-ssh-slowpesh | EXPLOITABLE | reachable | нет |

**Метрика ценности — cleared rate**, а не корреляция с govulncheck.
Кейс «cleared», когда анализатор выносит доказанный негатив:
`NOT_AFFECTED` (deterministic affected-chain) или `NO_EXPLOIT_PATH_FOUND`
(VERIFIED falsifier на mandatory-условии). `EXPLOITABLE`, `INCONCLUSIVE` и
`UNKNOWN` оставляют кейс на человеке — для triage «reachable» и
«не доказали безопасность» эквивалентны. Текущий прогон: **13/37 cleared**:
11×NOT_AFFECTED deterministic (в том числе `real-micro-plain` при
module-only finding govulncheck) и два verified-негатива NEPF:
`real-unix-stat` — продукт не трогает `unix.Faccessat`,
а единственный dep-internal caller `unix.Access` доказанно мёртв —
нет product refs, нет caller'ов внутри `x/sys`, сторонних модулей,
импортирующих пакет, в dep-графе нет. NEPF без referenceable-субъектов
не выносится (`productReferenceable` гейт), а dep-internal invocation
учитывается transitively (`depSiteLive`): ssh-keyparse и dns-marshal в
INCONCLUSIVE — их прежний NEPF стоял на vacuous «zero product refs»;
jwt-auth — missing-call гейт. Второй NEPF — `real-micro-plain-6443x`
по контракту defect-locus (B30, spec §8): `L` = advisory-declared set
минус записанные экспертные non-locus решения (`non_locus` в кейсе —
основание с authority; автоматическое исключение запрещено — текстовое
несовпадение означает «соответствие не установлено», а не чистое тело;
review-контрпример с переименованной переменной это ловит). Для символов
без defect-site anchor'а модуль порождает `ProposedNonLocus` —
draft-исключения с записанным наблюдением, не участвующие в вердикте;
эксперт утверждает их переносом в `non_locus` (через `--non-locus-basis` или флаг `--accept-locus-proposals`). Отчёт печатает блок
**Машинная оценка**: предлагаемая оценка (МОЖНО ОТКЛОНИТЬ /
МОЖНО ОТКЛОНИТЬ ПОСЛЕ ПОДТВЕРЖДЕНИЯ / ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)), для каждого символа L —
статус пакета и требуемое экспертное решение (утвердить рекомендацию об исключении,
либо перепроверить отметку «вероятное место уязвимости»), плюс список допущений вне
машинной проверки (полнота advisory, корректность expert-решений, соответствие
параметров сборки окружению развёртывания). Аудит кода продукта не требуется —
вопрос уровня advisory: ограничен ли дефект этими пакетами. При
исключении transport-символов `L={RouteAndProcess}` — faulting индекс
`authority[0]` по fix PR9365; единственный locus-пакет отсутствует в
`go list -deps` графе продукта — код дефекта физически не слинкован.
Итоговый раздел отчёта `## Tracker-ready rationale` (а также вывод CLI `analyze`)
формирует связное человекочитаемое обоснование на русском языке, готовое для
вставки в задачу трекера: статус вердикта, подтверждение версии
библиотеки и корректности сканера (отсутствие false positive по версии), контекст
снимка и репозитория, суть дефекта, факты о сборке и точках экспозиции продукта,
обоснование безопасности вспомогательных функций в скомпилированных пакетах
и остаточный риск.
Парные контроли: `real-micro-plain-6443` без basis даёт EXPLOITABLE
(necessity машиной не замкнута — declared символ в трейсе → `C-LOCUS`
TRUE, консервативный позитив совпадает с govulncheck), mode-on и
factory-обёртка дают
EXPLOITABLE (локус в трейсе/внутримодульной цепочке),
pkg-present-func-absent даёт INCONCLUSIVE — наличие пакета в графе не
доказывает недостижимость функции. Boundary-контроли (неполная fix
series, rename, два независимых дефекта, upstream-only fix) покрыты
юнит-тестами на `testdata/locuslib`. Условие `C-LOCUS` не зависит от
наличия fix-diff: при падении fetch `L` = declared set − basis и
аннотации/proposals просто отсутствуют (ранее гейт молча снимался).
Отдельная граница falsifier'а — покрытие build-вариантов: файлы
продукта, исключённые записанным контекстом (`//go:build`,
GOOS/GOARCH-суффиксы, cgo), но импортирующие пакет локуса, переводят
negative verification в INSUFFICIENT_SCOPE (контроль `gated-scope` в
`corpus.json`: вызов `vuln.Parse` за `//go:build special` — отсутствие
пакета в дефолтном `go list -deps` не доказывает отсутствие при другой
конфигурации).
Цель B23 — поднять долю честных cleared
за счёт falsifier-доказательств, не объявляя недоказанное безопасным.

Для сравнения со standalone govulncheck важен более узкий показатель:
**signal-cleared rate = 2/26** на этом прогоне. Знаменатель — кейсы,
где govulncheck сообщил `reachable` или `package-level`; числитель —
verified-негатив анализатора при таком сигнале (`real-unix-stat`,
`real-micro-plain-6443x`).
Finding только с модулем учитывается отдельно (`module-level`), без
приписывания ему присутствующего уязвимого пакета. Остальные cleared
имеют `govulncheck: silent` или `module-level`.

Эта метрика частично доказывает дополнительную пользу относительно
govulncheck: `real-micro-plain-6443x` — первое reachable-отклонение,
которое standalone govulncheck не выносит (он сообщает трейс до
`HandleStreams` и останавливается — OR-семантика declared symbols не
различает defect locus); получено через записанное экспертное основание,
не автоматическим исключением. `real-unix-stat` добавляет negative
verification к package-level информации. Двух кейсов недостаточно
для вывода о надёжности или экономии ручного triage; необходимость
локуса опирается на полноту declared set и корректность экспертных
исключений (см. spec §8), а переносимость на другие классы дефектов
не проверена. `false-safe=0` означает совпадение с разметкой,
не независимую верификацию самой разметки.

Дополнительный контроль двух прежних cleared: прямой JSON govulncheck
для micro-plain содержит только модуль, а `go list -deps -test` не
содержит xDS/RBAC-пакетов. Для linux/arm64 unix-stat сборка с
`-gcflags=all=-l` не содержит символа `unix.Faccessat`; парный
unix-access его содержит и получает EXPLOITABLE/reachable. Эти
контроли поддерживают конкретные отрицательные результаты, но не
являются доказательством надёжности механизма на других продуктах.

Негативный exploit-claim несёт именованный falsifier; финальный
`NO_EXPLOIT_PATH_FOUND` требует и его, и `VERIFIED` negative verification.
Неполное происхождение аргумента (включая пустой origin) остаётся
`UNKNOWN`, включая guard-кандидаты с unresolved dep-flow. FALSE-кандидат
требует полного ingress closure: безопасны все inventoried inputs и
автономные источники product-reachable dependency cone. Пустой `Reaches`
не исключает источник: отсутствие найденного пути не доказывает
невозможность стать payload.

Полнота модели (B30): advisory-declared sink, не прошедший source-
resolution (символ в affected package не найден в dep source — vendored
без пакета, internal-ветка не в сборке), попадает в
`ExploitModel.UnresolvedSubjects`. Любой такой субъект блокирует
`EXPLOITABLE` (модель не покрывает его exploit shape) и ограничивает NEPF
фальсификаторами, покрывающими весь declared set (`govulncheck-silence`,
`no-module-usage`, `unreached-exported-subject`); falsifier на аргументах
resolved-sink'ов при непустом UnresolvedSubjects NEPF не даёт.

Альтернативная sink-closure стратегия спеки §5.2 требует отдельного
проверенного контракта полноты, привязанного к advisory, версии и
mandatory condition. `OSV imports.symbols` задаёт только `KNOWN_ONLY`;
production-пайплайн сохраняет sink inventory для аудита, но не выставляет
полноту по одному этому списку. Поэтому `real-protojson-const` остаётся
INCONCLUSIVE: локальные константные payloads не закрывают возможный sink
вне известного списка, а ingress содержит `detrand` и непроверенную
семантику вызовов. Остаток — B26 в каноническом backlog.

Регрессионные контрпримеры проверяют переданный внешний ввод через func
values, переназначенные callbacks, `os.LookupEnv`, несколько `init()`,
package initializers, форматирование с `String`/`Format` callbacks,
void stdlib callbacks, `reflect.Indirect`, `complex` и `recover`.
Непроверенный вызов сохраняет UNKNOWN. Dep pins снимаются после каждой
closure query; эвикция кэшей и bodyless declarations не должны приводить
к панике. Смена dependency scope во время сканирования не разрешает
кешировать неполный результат как полный. Provenance локальной переменной
объединяет присваивания с заполнением через out-parameters, slice writes
и receiver mutations: `make` не стирает данные последующего `io.ReadFull`.

Дифференциация относительно standalone govulncheck:

- `real-ssh-keyparse`: govulncheck видит пакет без symbol-trace
  (package-level). Раньше «zero product references» верифицировал FALSE →
  NEPF; после фикса это вакуумно для unexported sinks — кейс честно
  INCONCLUSIVE до dep-internal негативной проверки (B24).
- `real-micro-xds` (GO-2026-6441): все sinks в `internal/…/rbac` —
  «no product refs» не может быть falsifier по visibility-правилам;
  гейт `productReferenceable` в `Verifier` блокирует такие VERIFIED →
  ранее ложный NEPF (false-safe), теперь честный INCONCLUSIVE.
- `real-jwt-auth`: missing-call advisory — `Valid()` не зовёт
  `VerifyAudience` by design. Dep-invocation гейт видит: субъект мёртв,
  но sibling-методы того же receiver'а вызываются на живом dep-пути →
  «отсутствие вызова» не может обосновать негатив → INSUFFICIENT_SCOPE →
  честный INCONCLUSIVE (истина EXPLOITABLE; should-call семантики в
  модели нет, поэтому дальше INCONCLUSIVE не дожимается).
- getter-кейсы: registry-dispatch в go-getter (`getters[scheme].Get`)
  резолвится через iface→impl рёбра ModuleInternalReach; func-value
  opaque dispatch помечен → unreached субъекты UNKNOWN, не FALSE.
  Dispatch-narrowing (B23): iface→impl рёбра и iface-caller'ы сужены до
  типов, реально инстанцированных в загруженном коде (`new`/`T{}`/`var`/
  `make`/конверсии; отключается при `reflect.New`/`unsafe`/`plugin`/
  linkname), dep-caller'ы и field-write'ы — до product-driven конуса
  модуля, а per-callsite `g = registry[key]` — до impl'ов по
  вычисленным const-ключам (инициализаторы `T{F:}` на receiver-инстансах,
  `init`, knowledge string-semantics: `Detect`-identity для schemed URL,
  `forced_split`, `subdir_split`, `url.Values.Get` по `Query()`).
  **Важно про getter-const**: INCONCLUSIVE там — честный вердикт, не
  пробел: `HttpGetter.Get` переиспускает `Get(dst, source)` с `source`
  из server-controlled `X-Terraform-Get` header / meta-тега → тот же
  синтаксический сайт `c.Getters[force]` обслуживает и outer (const),
  и nested (не-const) инстансы → ключ не вычисляется → сайт остаётся
  unrestricted → `GitGetter` реально reachable через protocol-switch.
  NEPF здесь был бы false-safe.

Заметка про отчётность: verdict-reasons и таблица «Affected analysis»
называют проверенный предмет — `modules probed` / `packages probed`
(что именно искали в `go list -m all` / `go list -deps -test ./...`) и
evidence-id; INCONCLUSIVE перечисляет unresolved condition-ID. Пустой
probed-набор (advisory без package-записей) даёт UNKNOWN, не FALSE —
проверять нечего, отсутствие не утверждается.

Multi-module advisory: `packages probed` включает записи всех
affected-entries, включая pending (модуль в графе, версия
нерезолвабельна — stdlib toolchain без `go version` факта или dep
без `Version`). Linked только pending-модуль → `version_affected`
остаётся UNKNOWN с limitation — версия другого, нелinked entry не
приписывается; `resolved_version` и `selected_module` привязаны к
подтверждённо-linked entry, а linked pending-модули выводятся строкой
`modules version-unresolved` — version-fact не применяется к условиям
чужих модулей. Usage- и negative-проверки сканируют все linked-модули,
а доказательства атрибутятся по модулю владельца субъекта (владелец —
наибольший совпадающий модульный префикс). Владелец вызываемого пакета
берётся из графа импортов продукта: nested-модуль `dep/v2` не
абсорбируется родителем `dep`, даже когда `dep/v2` отсутствует в
affected-entries. Вызов с неизвестным владельцем или владельцем вне
linked-модулей не доказывает usage и блокирует вывод об отсутствии:
вложенный модуль может вызывать родителя транзитивно. `VersionFact`
учитывает оба поля субъектов
(`Subject` и `Subjects`); условие без субъекта при нескольких linked-модулях
остаётся UNKNOWN.

## Scalability (закрытый OOM)

Исторический OOM (`hashicorp/go-getter` съедал память хоста) закрыт:
dep-syntax грузится только для пакетов из `loadExtra`-паттернов
(`NeedDeps` убран), `extraPkgs`≤64 patterns/≤40 пакетов/≤500 файлов
с LRU-эвикцией и очисткой AST-удерживающих кэшей, вес паттерна
взвешивается и по транзитивному import-closure (≤2500 types-пакетов —
один aws-scale пакет тащит сотни stub-типов через
`types.Package.Imports()`); `NeedImports` убран (import-граф читается
через `types.Package.Imports()` — иначе каждый retained-пакет удерживал
транзитивные stub-деревья типов, ~12GiB на getter-const), `callerCache`
≤8192, advisory-модуль пинится на время closure-верификации (крупные
модули остаются эвиктируемыми — conservative), `callAt` догружает
пакет сайта по `file=`-запросу, если его load-инстанс эвиктнут,
per-trace `classifyCache` сворачивает экспоненциальный caller-fan-out
(yaml-file 413s→8s), `why`-строки capped в точках композиции (md-render
6.5GiB→8s), `txBuf` дедуплицируется и ограничен (миллионы CallSite-
записей ≈2.2GiB — главная аллокация getter-const), `evalBudget`
ограничивает fan-out одного трейса во всех trace-сессиях (getter-const
>10min→80s), `--mem-limit` watchdog с hard-exit >150% ~1s и принудительным
`debug.FreeOSMemory()` (HeapSys считает held-спаны, а не live heap).
Эвикция всегда в безопасную сторону: меньше покрытия → UNKNOWN, а не
ложное отсутствие. Getter-кейс: INCONCLUSIVE, память ограничена
эвикцией.

Текущий контроль `real-ssh-slowpesh` завершился EXPLOITABLE за 905с.
Expression budget действует на отдельную payload-позицию; он не
ограничивает всю enumeration и повторные dependency loads после
эвикции. Общий deadline/work budget closure query остаётся B28.

## Статус: первый слой реализован

`eval/live-corpus.json` + `eval/advisories/live/*.json` — 11 advisory
`github.com/rabbitmq/amqp091-go` (все фиксированы v1.13.0; продукт на
v1.10.0 → affected по версии) против `продукт-референс`. Путь к
репозиторию продукта — `${VA_PRODUCT_REPO}` (env-экспансия) или флаг
`--repo`; конкретный локальный репозиторий не коммитится.

## Прогон

```
PATH=$HOME/go/bin:$PATH VA_PRODUCT_REPO=<product-repo> analyzer eval --corpus eval/live-corpus.json
```

Требования: сеть (root-cause резолвер тянет fix-patch по commit-refs из
advisory) и `govulncheck` в PATH. Без govulncheck reachability идёт через
module-usage fallback — вердикты могут честно смещаться к INCONCLUSIVE.

Результат (детерминистичный прогон, govulncheck v1.8.0):

| Группа | Кейсы |
|---|---|
| EXPLOITABLE | GHSA-4v58, c5pq, r9c8 — доказан внешний payload на wire-parser/exhaustion путях |
| INCONCLUSIVE | GHSA-27gv, 33mj, 465g, j497 — deploy/config-dependent условия; GHSA-6c5v, xwwf, GO-2026-6372 — фактический peer payload не доказан через fix-subjects/opaque вызовы; GHSA-rm6m — unresolved dep-flow не позволяет верифицировать полноту bound-гардов |

`expect` в корпусе пиннит **ground truth** — истинный вердикт каждого
кейса размечен вручную по advisory+коду продукта; метод и обоснования —
[`ground-truth.md`](ground-truth.md). `INCONCLUSIVE` в expect допускается
там, где истина определённа, но механизм её доказательства пока не
реализован (33mj — PLATFORM_CONDITION по go_version; 465g — reflect-
демоция без значения типа; 6c5v/xwwf/GO-2026-6372 — peer payload;
rm6m — полнота guard coverage). false-safe=0 остаётся стоп-критерием.

После B2: кейсы, доходящие до GAP_ANALYSIS, без `--allow-exec` несут
limitation «build/test evidence actions skipped»; с флагом — BUILD/TEST
evidence, `go build`/`go test` в tool_executions и секция «Build & test»
в отчёте. На вердикты не влияет.

После B3 (vendor-internal provenance, §3.5): для unexported dep-субъектов
peer-input условий собираются настоящие dep-internal call sites и flows —
resolved origin решает claim вместо эвристики «module usage →
peer-driven» (эвристика остаётся fallback, когда dep-trace пуст или
UNKNOWN). На живом amqp091 ожидаемое поведение: `readField`-цепь упирается
в interface dispatch (`m.read(r)`) → trace UNKNOWN → эвристика сохраняет
TRUE. Наличие resolved flow направляет claim в provenance evaluator;
это может оставить UNKNOWN, если origin известен, но роль payload
не доказана. Claims несут dep-flow evidence/limitations. Fixture-корпус
расширен до 18 кейсов (`wire-dep-peer` → EXPLOITABLE через resolved
EXTERNAL_UNTRUSTED). `wire-dep-const` → INCONCLUSIVE: локальный
константный аргумент разрешён, но модуль одновременно получает peer
input; полная ingress closure небезопасна, а единственный известный
sink не несёт отдельного доказательства полноты. Проверка не исключает
другие источники по отсутствию найденного пути к этому символу.

После ревью closure-логики live 6c5v/GO-2026-6372 и xwwf допускают
INCONCLUSIVE при сохранении ground truth EXPLOITABLE: opaque `pick`
и fix-subjects `openTune` не доказывают происхождение фактического
уязвимого payload. Полноценный позитив требует независимого трейсинга
peer tune/header/body; остаток scope mismatch отмечен в B15. Сетевой
writer в неизвестной payload-позиции не доказывает входные данные:
его внешний origin сохраняется, но positive payload evidence остаётся
неполным, а отрицательная проверка продолжает учитывать этот flow.

## Что прогон валидировал на живом коде

- Root cause из fix-commit refs (no symbols в advisory → патч →
  `readField` SINK).
- WIRE_PARSER exploit model: peer-input/constraint conditions через
  govulncheck trace.
- **REVIEW→REPAIR петля в деле**: GHSA-27gv — C-EXPOSED демотирован
  high-severity finding'ом (reflect usage расширяет call graph) →
  re-review ACCEPT → честный INCONCLUSIVE вместо слабого FALSE.
- Exposure-факты реального репо: inbound listeners (http/grpc/net) и
  outbound amqp091.Dial* в отчёте.

## Ground-truth pass (2026-…)

Ручная проверка 5 EXPLOITABLE-кейсов по персистированным кейсам:

- **RC accuracy 5/5**: `readField` (field-length DoS), `readLongstr`
  (int-overflow), `writeFrame` (shortstr trunc), `Channel.recvContent`
  (body OOM), `Connection.openTune` (frame-size negotiation) — каждый
  символ подтверждён присутствием в persisted fix-diff evidence, что
  соответствует содержанию advisory.
- **Coverage ответ**: GHSA-advisory отсутствуют в Go vuln DB →
  `govulncheck_coverage=not_in_db`, reachability выводится по
  module-usage (44 call-сайта amqp091 API) с limitation «transitive
  reach inferred, not traced to the sink». Это специфицированная
  семантика WIRE_PARSER: unexported sink исполняется в peer-driven
  read-path на каждом кадре — вызов API подразумевает исполнение
  парсера. EXPLOITABLE корректен в threat-модели «враждебный/MITM
  брокер».
- **Найденный дефект (исправлен)**: при отсутствии `govulncheck` в
  PATH бинарь `go install` (GOBIN/GOPATH/bin/~/go/bin) не резолвился →
  tool не запускался, а объяснение говорило «advisory absent from
  govulncheck DB» — неправильная атрибуция. Теперь `resolveGovulnBin`
  ищет в GOBIN/GOPATH/bin/~/go/bin, а `libraryUsageVerdict` получает
  явную причину fallback'а (`did not run or failed` vs `absent from
  DB`).

Остаётся: качественная оценка «peer can drive» → «истинно exploitable
в проде» зависит от деплоя (доверен ли брокер) — за пределами
статического анализа, claim limitations это фиксируют.

## Ground truth (B1)

Истина по всем 11 кейсам размечена вручную по fix-diff advisory + коду
продукта — [`ground-truth.md`](ground-truth.md). Метод: кто дёргает
уязвимый API (44 call site на `components/amqp09`: Dial/DialTLS/
DialTLS_ExternalAuth, Consume, Qos, Declare*,
PublishWithDeferredConfirmWithContext); исполняется ли `recvContent`/
`openTune` на продукционном пути; есть ли безусловный путь от
peer-данных до условия уязвимости (для j497 — нет, все peer→shortstr
пути config-contingent → INCONCLUSIVE). Разметка поймала два
false-safe бага: covered-entry без `AffectedSymbols` больше не
принимает govulncheck-сilenсe за negative evidence (6c5v,
GO-2026-6372 → EXPLOITABLE через записанные `ModuleReachable`-цепочки).

## Следующий слой

- Метрики root-cause accuracy (верные ли символы) и FALSE precision.
- Второй продуктовый репозиторий для диверсификации.
- Live-корпус не входит в CI-регрессию (сеть + тяжёлый репо) — отдельный
  прогон.

## rm6m ground-truth pass

GHSA-rm6m-hrcw-jw33 (amqp091 `Channel.Qos`, signed→unsigned cast →
flooding). Два отдельных вывода:

- **Class-label исправлен**: keyword-классификация была first-match —
  одиночный `frame` перекрывал плотный exhaustion-сигнал (5:1).
  Теперь `scoreKeywords` выбирает класс по частоте попаданий словаря
  (tie → более ранняя/специфичная строка). rm6m/4v58/r9c8 →
  `RESOURCE_EXHAUSTION` — тот же peer-driven паттерн, вердикты не
  сдвигаются, label в отчёте/limitation точнее.
- **Резидуальный gap (не закрыт)**: `Qos(r.prefetchCount, …)` — аргумент
  идёт из struct-поля (`r.prefetchCount ← setPrefetchCount(cfg)`),
  interprocedural field-flow за пределами трейсера (6 hops →
  UNRESOLVED, честно зафиксировано в hypothesis). Плюс продуктовая
  гарда — *sanitize-апдейт* без return (`count>1024 → 1024`), что
  outside текущего guard-продюсера. Реальный ответ скорее «не
  эксплуатируемо через конфиг», но система не может это доказать →
  корректный INCONCLUSIVE, не баг.

Остаток: caller-chain глубина — `count` (param setPrefetchCount) ←
`cfg.PrefetchCount` ← cfg-параметр конструктора ← reflect/mapstructure-
декод фреймворка: цепь >8 hops и терминально упирается в reflect-популяцию,
которую статически не резолвить — честный terminal UNKNOWN.

После фиксов: arg0 `Qos` резолвится полностью — `r.prefetchCount` ←
`count` (param setPrefetchCount) ← `cfg.PrefetchCount` ←
`mapstructure:"prefetch_count"`-тег → **CONFIGURATION** (hypothesis
CONFIRMED). Sanitize-switch кламп (`count<0→0`, `count>1024→1024`)
записан Guard=true + Covers — значение ограничено на всех write-site'ах.
arg2 (`global=false`) — CONSTANT (builtin-иденты больше не UNKNOWN).

Что держит INCONCLUSIVE: config-origin → deployDependent —
CONFIGURATION-ввод может быть attacker-influenced (хостильный конфиг),
поэтому peer-input FALSE не утверждается. Финальная цепь честная:
peer-input UNKNOWN (deploy-dependent), constraint TRUE (LLM-агент
по fix-diff — безопасное направление), вердикт INCONCLUSIVE.

Следующий раунд фиксов (per-arg + range-gated):

- **Per-arg deep-trace**: gap-loop и NV теперь работают по `f.Arg`, а не
  всегда по `cond.ArgIndex` — arg1 больше не пропускается; ключи
  планировщика и `ReplaceDataFlow` матчат (cond, sink, arg). Все три
  аргумента `Qos` резолвлены: arg0/arg1 → CONFIGURATION
  (mapstructure-теги через полные цепи field→setter-param→caller→cfg),
  arg2 → CONSTANT.
- **Range-gated sanitize-switch**: `setPrefetchSize`-форма —
  switch сравнивает `size`, присваивает `prefetchSize`; default-ветка
  `fs = FileSize(size)` засчитывается bounded, когда compared-var
  ограничен с двух сторон (`size<0` и `FileSize(size)>max`), и default
  присутствует. Без default или при односторонней границе — не гарда
  (onesidedprod-фикстура). Accessor-обёртки `int(fs.Bytes())` в RHS
  write-site разворачиваются к локалу.
- **NV re-trace на глубоком бюджете** (`verifyHops=16`): раньше
  verifyInputFalse перетрейсил на depth=2 и объявлял UNKNOWN-origin
  «contradicted». Теперь UNKNOWN → INSUFFICIENT_SCOPE (отсутствие
  доказательства ≠ контрадикция), а реально внешние/конфиг-ориджины →
  CONTRADICTED. LIVE: NV для C-PEER-INPUT честно показал полную цепь
  до `cfg.PrefetchCount` mapstructure-тега и корректно контрадиктнул
  агентский FALSE (config = deploy-dependent).
- **LLM-tool panic**: `find_validations` с arg_index=-1 падал в
  `call.Args[-1]`; теперь -1 делегирует в `FindAllValidations`.
- Const/generated-аргументы не требуют Covers — константа не нарушает
  constraint (`arg2=false` не блокирует guard-coverage).

Bound-параметр C-CONSTRAINT теперь честный: `prefetchCount < 0 or
prefetchSize < 0` — signed→unsigned cast именно в этих аргументах.

Финальный раунд (порядок стадий + точность демоции):

- **LLM-fallback перенесён в конец GAP_ANALYSIS** — раньше агент
  выставлял TRUE до deep-trace и вытеснял доказуемый det-FALSE. Теперь
  `C-CONSTRAINT` детерминистично достигает `falsifier=guards` +
  NV **VERIFIED** («all 3 sink site(s) covered»: arg0/arg1 клампы,
  arg2 const-skip).
- **Точные dynamic-маркеры**: `reflect` импорт больше не ослабляет
  guard-FALSE (import ≠ write); добавлен `reflect_write` —
  `reflect.Value.Set*`, ослабляет только при exported-полях
  (`prefetchCount`/`prefetchSize` unexported → reflect их не пишет).
  `unsafe` остаётся ослабляющим — `unsafe.Pointer` пишет и unexported.
- **Review-демоция остаётся**: ревьюер демотировал VERIFIED-FALSE по
  unsafe-маркеру — консервативно корректно (unsafe действительно
  обходит синтаксическое покрытие). Итог INCONCLUSIVE с полным следом:
  доказанные bound-гарды + записанная причина, почему FALSE не
  утверждается.
- **Отчёт**: таблица Claims теперь показывает колонку verification
  (`guards / VERIFIED (demoted)`) — история доказательства видима,
  а не только финальный результат.

Итоговая доказательная цепочка rm6m (финал): sink аргументы →
field-writes → setter-параметры → callers → `cfg.*` mapstructure-теги →
CONFIGURATION + Covers bound-гарды + NV VERIFIED → **вердикт
NO_EXPLOIT_PATH_FOUND** — первый доказуемый негативный результат на
живом кейсе.

Что сняло последнюю демоцию: `unsafe` в продукте встречается только как
read-only `unsafe.Slice/StringData` (fastbytes) — ни одной
`unsafe.Pointer`-материализации, поля `prefetchCount/Size` unexported
(reflect.Set недостижим) и `&r.prefetch*` нигде не берётся →
write-site покрытие полное, ревьюеру не на что демотить выше medium.

Последующий раунд — формальный bound: `params.bound` перестал быть
аннотацией. `field-write prefetchCount` несёт [0,1024],
`field-write prefetchSize` — [0,1GiB]; оба дизъюнкта
`prefetchCount < 0 or prefetchSize < 0` численно контрадиктят →
claim содержит «bound verified: every disjunct … is excluded by
recorded clamp ranges». Два дефекта ловились на живых прогонах:
name-matched гарды из других conditions фильтровались по arg-индексу
(чинено — name-match снимает arg-фильтр, coverage-фильтр по sink-файлу
остаётся), и LLM-ревьюер демотировал FALSE как «противоречащий
root cause» — промпт дополнен семантикой claim'ов (FALSE на exploit-
condition = безопасный результат про продукт, не опровержение advisory;
VERIFIED+demoted — ожидаемая история, не внутреннее противоречие;
демоция только по конкретному артефакту), а REPAIR_ANALYSIS теперь
детерминистически отклоняет демоцию VERIFIED-FALSE, если названный в
`problem` артефакт (dynamic-маркер, site, traced origin, evidence-id)
не записан как ослабляющий для этого claim'а — semantic-misread finding
понижается до advisory concern на claim'е. Вердикт
NO_EXPLOIT_PATH_FOUND воспроизводим в корпусе; INCONCLUSIVE остаётся
допустимым ожиданием — LLM-ревью недетерминирован.

Дополнительная гарантия покрытия: `fieldWriteGuards` теперь отклоняет
Covers при `&x.f` address-taken — запись через pointer-alias невидима
синтаксическому скану write-site'ов (фикстура `addrtakenprod`,
`unsafe_write`/`unsafe_ptr` маркеры в `reflectprod`).

Это и есть «доказуемый» уровень: каждое утверждение опирается на
записанное evidence, а отказ от FALSE — на конкретный маркер
(unsafe_ptr/unsafe_write/address-taken/exported-reflect-write), а не на
«не нашли путь».
