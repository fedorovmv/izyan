# Спецификация дополнительной ценности анализа поверх govulncheck

Статус: reviewed draft; READY для плана реализации.

## 1. Проблема

`govulncheck` уже определяет наличие уязвимого пакета и строит доступный
ему путь до affected symbol. Повторный поиск того же пути собственным
анализатором не оправдывает отдельный сложный статический анализ.

Дополнительная сложность оправдана, только если анализатор проверяет
обязательные условия эксплуатации, которые не входят в контракт
`govulncheck`, и выдаёт product-specific результат с воспроизводимым
доказательством.

Основной проверяемый сценарий:

```text
govulncheck: reachable или package-level
    -> выделить обязательные условия конкретной уязвимости
    -> проверить их на snapshot продукта
    -> доказать FALSE, доказать TRUE либо сохранить UNKNOWN
    -> выдать результат, который нельзя получить из reachability alone
```

## 2. Цель

Анализатор ДОЛЖЕН отличать:

1. достижимость affected symbol;
2. выполнение обязательных условий эксплуатации;
3. полноту доказательства по каждому условию.

Первый реализуемый срез ДОЛЖЕН доказывать отсутствие attacker-controlled
input, когда `govulncheck` сообщает reachable, а выбранная стратегия
полноты доказывает, что ни один внешний источник не способен передать
payload в affected sink.

Постоянный аргумент product→dependency сам по себе не является таким
доказательством: dependency может получить другой payload из сети, файла,
callback, mutable state или неизвестного преобразования. Срез считается
успешным только при полном coverage выбранной стратегии. Частичное
покрытие заканчивается `UNKNOWN`/`INCONCLUSIVE`.

## 3. Что считается дополнительной ценностью

Результат имеет дополнительную ценность относительно standalone
`govulncheck`, если выполнено хотя бы одно условие:

- **signal cleared**: на `reachable`/`package-level` сигнале получен
  `NOT_AFFECTED` или `NO_EXPLOIT_PATH_FOUND` с требуемым доказательством;
- **exploit confirmed**: `EXPLOITABLE` опирается не только на call path,
  но и на product-specific evidence всех остальных обязательных условий;
- **bounded unknown**: `INCONCLUSIVE` называет конкретное неразрешённое
  обязательное условие, недостающий факт и проверку, которая способна
  изменить verdict.

Для первого среза критерием является только `signal cleared` через
falsifier `constant-or-generated-input`. Остальные два направления
фиксируют дальнейшее развитие и не входят в его done-критерий.

Не считаются дополнительной ценностью:

- `EXPLOITABLE`, полученный только из reachable call path;
- `NOT_AFFECTED` на fixed version, когда standalone `govulncheck` молчит;
- пересказ advisory или вывод LLM без верифицированного evidence;
- remediation-команда или созданный commit сами по себе;
- снижение `INCONCLUSIVE` ценой ослабления negative verification.

## 4. Инварианты

Действуют все главные инварианты проекта. Для этого среза обязательны:

- отсутствие найденного пути не доказывает отсутствие пути;
- `FALSE` требует именованный falsifier и negative verification;
- неполный coverage выбранной стратегии запрещает `VERIFIED`: для sink
  closure это affected sinks и все способы записи их payload; для ingress
  closure это все входы и автономные источники reachable dependency cone;
- control-flow путь boundary→sink не доказывает перенос данных между
  аргументами; требуется отдельное payload-flow evidence;
- `OriginUnknown`, пустой или неизвестный будущий origin означает
  неполный scope, а не безопасный input: до построения `FALSE` это
  `UNKNOWN` с limitation; во время negative verification это
  `INSUFFICIENT_SCOPE`;
- configuration, database, internal service и authenticated external
  остаются deployment-dependent и не считаются безопасными;
- reflection, unsafe, plugin, linkname, function values и непрозрачный
  dispatch, способные добавить путь или запись, блокируют безопасный вывод;
- метка `GENERATED` без доказательства происхождения всех входов генератора
  и отсутствия автономных внешних чтений не считается безопасной;
- LLM может предложить mapping аргументов или семантику, но только
  детерминистически подтверждённый mapping участвует в claim.

## 5. Модель анализа первого среза

### 5.1. Предмет проверки и два независимых графа

Для mandatory condition вида «атакующий контролирует payload, достигающий
affected sink» анализатор выбирает одну из двух форм доказательства.

При **sink closure** строится набор:

```text
affected sinks
    <- dependency-internal payload-flow
    <- product→dependency boundary entries
    <- payload arguments at each entry
    <- product-side origins of those arguments
```

Boundary entry — вызов из product module в affected module либо в другой
dependency, из которой доказан путь до affected sink.

Анализ хранит два разных отношения:

- **control reach**: функция/метод может вызвать следующий узел;
- **payload flow**: конкретное значение из аргумента, return, receiver,
  field или local действительно передаётся в конкретный payload-аргумент
  следующего узла.

`ModuleInternalReach` может быть evidence только для control reach. Его
цепочка без payload-flow mapping не подтверждает ни безопасный, ни внешний
origin у sink.

Внутренний вызов dependency не считается новым product input. Origin
payload должен прослеживаться по payload-flow до product-side значения
либо до автономного источника внутри dependency.

При **ingress closure** анализатор не обязан знать каждый sink. Вместо
этого он начинает со всех входов в dependency cone, достижимый из
продукта, и всех автономных sources внутри cone. Для каждого входа он либо
доказывает безопасный origin, либо отдельно доказывает, что значение не
может стать payload ни на одном достижимом пути. Это более консервативная
стратегия: внешний input блокирует её, даже если связь этого input с
известным sink не найдена.

### 5.2. Полнота proof scope

Кандидатный sink set строится как объединение:

- affected symbols из advisory;
- верифицированных root-cause sinks;
- релевантных symbols из всех заявленных fix commits;
- явно переданных manual root causes с provenance.

Наличие этого объединения не доказывает его полноту. Advisory symbols,
один fix diff и результат `ModuleInternalReach` сами по себе считаются
списком известных кандидатов.

Статус sink set `COMPLETE` допустим только для конкретного mandatory
condition и диапазона версий при наличии одного из оснований:

- authoritative source явно объявляет список исчерпывающим и задаёт его
  scope;
- отдельный advisory-scoped proof artifact перечисляет использованные
  advisory, root-cause artifacts и полную fix series, содержит проверенное
  утверждение о полноте и evidence IDs;
- детерминистический source scan перечисляет все совпадения с формальным
  sink predicate, а completeness evidence отдельно доказывает, что этот
  predicate полностью выражает проверяемое mandatory condition.

Если нет явного exhaustive claim, version/condition binding, хотя бы один
сосланный artifact недоступен, fix series неполна, root cause неоднозначен
либо возможен sink вне формального predicate, статус остаётся
`KNOWN_ONLY`.

Advisory-scoped proof artifact привязан к vulnerability ID, module,
диапазону версий и mandatory condition. Он поступает вместе с данными
конкретного advisory/case и сохраняется в evidence отчёта. CVE-specific
утверждение о полноте запрещено хранить во встроенной
`internal/goanalysis/knowledge.json` или передавать через `--knowledge`:
эти механизмы содержат только генеральную семантику API.

Для отрицательного вывода анализатор ДОЛЖЕН использовать одну из двух
стратегий полноты:

1. **Sink closure**: источник с зафиксированным контрактом полноты явно
   утверждает, что перечислены все sink данного mandatory condition, а
   каждый элемент найден и верифицирован в анализируемой версии. Для
   каждого sink затем перечисляются все payload inputs и все способы их
   записи;
2. **Ingress closure**: анализ не зависит от полноты sink set и доказывает,
   что во всём dependency cone, достижимом из продукта, перечислены все
   входы: каждый аргумент, receiver и доступное состояние переданного
   объекта на product boundary, callback registrations/results и
   автономные источники dependency. Для каждого входа доказан безопасный
   origin либо невозможность стать payload ни на одном достижимом пути.

Контракт полноты sink set должен быть отдельным persisted фактом с
provenance и evidence IDs. Если источник не обещает полноту, отсутствует
часть fix series или root cause остаётся ambiguous, использовать sink
closure нельзя. В этом случае отрицательный вывод возможен только через
полностью замкнутый ingress closure; иначе claim остаётся `UNKNOWN`.

Текущие `Vulnerability.AffectedSymbols` и `RootCauseModel.RootCauses` не
несут такого контракта. По умолчанию они имеют scope `KNOWN_ONLY`, даже
если получены из authoritative advisory. Для `sink closure` реализация
должна добавить явный scope status `COMPLETE` с основанием; простой
manual список или эвристически разобранный fix diff не может выставить
его автоматически.

### 5.3. Payload и source closure

При sink closure для каждого payload-аргумента каждого sink выполняется
обратный трейс по всем writers до одного или нескольких терминальных
источников. Каждый шаг ДОЛЖЕН показывать, какое значение передано через
parameter, return, receiver, field write/read, local assignment или
подтверждённую transformation. Автономный источник вне всех доказанно
полных reverse-flow к sink не блокирует эту стратегию.

При ingress closure анализатор вместо reverse-flow от известных sink
строит полный inventory всех входов во всём reachable dependency cone.
Inventory без предварительной классификации включает каждый boundary
argument, receiver, доступное на boundary состояние переданного объекта,
callback input/result и автономный источник. Return/out/destination роль
не является основанием для исключения: существующее поле объекта может
быть позднее прочитано как payload.

Исключить элемент inventory можно только с отдельным evidence, что ни само
значение, ни достижимое через него состояние не способны стать payload ни
на одном достижимом пути. Неразрешённый alias, callback, набор field
writers/readers или роль аргумента означает `UNKNOWN`. Для оставшихся
элементов доказывается безопасный терминальный origin. Неизвестно, полный
ли inventory, также означает `UNKNOWN`.

Терминальный источник классифицируется так:

- product boundary argument;
- автономный источник dependency: сеть, файл, environment/config,
  database, internal service, callback result, mutable global/receiver
  state с неполным набором writers;
- константа;
- доказанно независимая генерация;
- неизвестный источник.

При sink closure автономный внешний или deployment-dependent источник
блокирует negative-кандидат, только если доказано или не исключено, что он
может записать payload проверяемого sink. При ingress closure любой такой
источник в проверяемом cone блокирует negative-кандидат. Неизвестный
источник, неизвестное преобразование, неразрешённый callback или неполный
набор field writers оставляет condition `UNKNOWN`.

`GENERATED` допустим как безопасный терминал только если evidence
показывает, что:

1. все входы генератора сами замкнуты на `CONSTANT` или уже доказанный
   независимый `GENERATED`;
2. тело генератора и вызываемый им замкнутый cone не читают автономные
   источники;
3. generator semantics детерминистически проверена по телу функции либо
   по versioned entry с генеральной семантикой API;
4. dynamic markers не позволяют заменить генератор или его входы.

Простая запись `Origin=GENERATED` без этих evidence означает `UNKNOWN`.

`real-getter-const` является обязательным контрпримером: constant URL на
product boundary не закрывает condition, потому что достижимый
`HttpGetter.Get` читает `X-Terraform-Get`/meta response и передаёт новое
значение в повторный dispatch. Такой источник должен давать `UNKNOWN` или
`TRUE` в зависимости от доказанности attacker control, но никогда FALSE.

### 5.4. Условия FALSE-кандидата

Evaluator может построить `FALSE`-кандидат только если одновременно
доказано:

1. выбрана и выполнена стратегия `sink closure` или `ingress closure`;
2. при `sink closure` доказана полнота sink set, для каждого sink построен
   полный reverse payload-flow по всем writers, а каждый терминальный
   source замкнут на `CONSTANT` или доказанно независимый `GENERATED`;
3. при `ingress closure` доказана полнота reachable dependency cone и
   inventory всех arguments, receivers, переданного object state,
   callbacks и автономных sources; для каждого элемента доказан безопасный
   origin либо невозможность стать payload ни на одном достижимом пути;
4. control reach нигде не используется вместо требуемого payload-flow или
   source inventory;
5. не найден dynamic marker или opaque edge, способный нарушить полноту
   выбранной стратегии: добавить sink/writer при sink closure либо
   entry/source при ingress closure;
6. coverage set выбранной стратегии явно записан в evidence.

Если любой пункт не доказан на evaluator-стадии, claim остаётся `UNKNOWN`
с limitation, falsifier не назначается и `NegativeCheck` не запускается.

### 5.5. Контракт negative verification

`NegativeCheck` работает только с уже построенным `FALSE`-кандидатом и
повторно получает scope и coverage выбранной стратегии другим проходом
либо на расширенном бюджете: sink set с reverse payload-flow или ingress
inventory reachable dependency cone.

- повторная проверка подтвердила тот же полный coverage set → `VERIFIED`;
- проверка не смогла воспроизвести полноту → `INSUFFICIENT_SCOPE`; claim
  может остаться FALSE-кандидатом в истории, но verdict его не использует
  и остаётся `INCONCLUSIVE`;
- найден внешний source или другой контрпример → `CONTRADICTED`, claim
  демотируется в `UNKNOWN`.

Таким образом, «FALSE не удалось построить» и «FALSE построен, но NV не
замкнул scope» являются разными наблюдаемыми состояниями.

### 5.6. Grouped subjects и роли аргументов

Exploit condition может содержать exported API и внутренние affected
symbols одной dependency. Анализатор НЕ ДОЛЖЕН трассировать все аргументы
всех grouped subjects как равноправные product inputs.

При sink closure анализатор ДОЛЖЕН:

1. определить boundary API, реально вызываемые продуктом;
2. отдельно доказать control reach и payload-flow от boundary API к
   affected sink;
3. сопоставить payload sink с соответствующим входным аргументом boundary
   API;
4. проверять origin только этого входного payload.

При ingress closure эта оптимизация неприменима без отдельного
non-payload proof. Все аргументы, receiver и доступное состояние
destination/output объектов сначала включаются в inventory. Исключение
допустимо, только если анализ всех достижимых aliases, readers, writers и
callbacks доказывает, что значение не может стать payload ни на одном
достижимом пути. Неразрешённая роль оставляет condition `UNKNOWN`.

## 6. Evidence и отчёт

Claim с falsifier `constant-or-generated-input` ДОЛЖЕН содержать либо
ссылаться на evidence, из которого можно восстановить:

- выбранную стратегию полноты и её coverage set;
- для sink closure: проверенные affected sinks, источник и статус полноты
  sink set, все payload writers и reverse-flow до терминальных sources;
- для ingress closure: границы reachable dependency cone и полный
  inventory arguments, receivers, переданного object state, callbacks и
  автономных sources; для каждого исключения — отдельный non-payload
  proof;
- относящиеся к выбранной стратегии boundary entries с `file:line`;
- control path boundary entry→sink, если используется sink closure;
- payload-flow edges между конкретными аргументами/значениями, если
  используется sink closure;
- payload arg index на boundary и sink, если используется sink closure;
- origin и краткую трассу каждого проверенного значения/source;
- найденные dynamic markers;
- итог negative verification и проверенный coverage set.

Отчёт ДОЛЖЕН объяснять product-specific отличие от baseline, например:

> govulncheck reaches yaml.Unmarshal; sink closure covers 1/1 affected
> sink and payload-flow maps its input to 1/1 product boundary argument;
> that argument is a build-time constant; no other source can feed the
> covered sink; negative verification VERIFIED.

Фраза «input constant» без предмета и coverage не является достаточным
обоснованием.

## 7. Eval-контракт первого среза

### 7.1. Обязательные регрессии

- generic fixture: constant boundary payload, доказанно переданный в sink,
  без других sources → verified FALSE;
- generic fixture: external product payload с доказанным flow до sink →
  TRUE;
- смешанные constant+external entries: при доказанном external→sink flow
  → TRUE; при неразрешённом flow → UNKNOWN; безопасный вывод запрещён;
- неизвестный origin до FALSE-кандидата → UNKNOWN с limitation, результат
  NV отсутствует;
- дополнительный opaque/dynamic entry → UNKNOWN;
- constant boundary argument + dependency network/file/callback source →
  UNKNOWN либо TRUE, если этот source способен питать sink; но не FALSE;
- dependency network/file/callback source, доказанно отделённый от всех
  payload-flow полного sink set, не блокирует sink closure, но блокирует
  ingress closure;
- ingress closure: объект передан как destination, но существующее поле
  затем читается на достижимом пути как payload → объект нельзя исключить;
  доказанный flow внешнего поля до affected sink даёт TRUE, а неизвестный
  sink/alias/origin даёт UNKNOWN; FALSE запрещён;
- call chain boundary→sink без argument mapping → UNKNOWN;
- неполный sink set без ingress closure → UNKNOWN;
- `GENERATED` с замкнутыми constant inputs и без автономных чтений →
  verified FALSE; голая/неполная GENERATED-классификация → UNKNOWN;
- evaluator не построил FALSE → UNKNOWN без NV; NV не воспроизвёл уже
  построенный FALSE → FALSE candidate + INSUFFICIENT_SCOPE, итог
  INCONCLUSIVE;
- sink closure с grouped exported/internal sinks → учитывается только
  доказанный payload mapping, выходные аргументы не примешиваются;
- boundary через промежуточную dependency → либо полный доказанный путь,
  либо UNKNOWN.

### 7.2. Real-dependency acceptance

После реализации:

- `real-yaml-const`: `NO_EXPLOIT_PATH_FOUND`;
- `real-protojson-const`: `NO_EXPLOIT_PATH_FOUND`;
- `real-yaml-http`, `real-yaml3-http`, `real-protojson-http` остаются
  `EXPLOITABLE`;
- `real-yaml3-const` остаётся `NO_EXPLOIT_PATH_FOUND`;
- `real-getter-const` остаётся `INCONCLUSIVE`;
- `false-safe=0`;
- `signal-cleared` меняется с `3/23` на `5/23`;
- `reachable-cleared` меняется с `1/17` на `3/17`.

Числа относятся к текущему development corpus и не являются прогнозом
для произвольного потока CVE.

### 7.3. Проверка на приватных продуктах

Внутренние репозитории и тикеты могут использоваться как закрытая
проверка переносимости механизма. Их исходники, пути, названия и факты
деплоя не коммитятся.

В публичной истории допустимо фиксировать только обезличенный результат:

- baseline category;
- класс проверенного mandatory condition;
- итог analyzer;
- сработал ли falsifier;
- причина `INCONCLUSIVE`, если falsifier не доказан.

Case-specific сведения из приватной проверки запрещено переносить в
`internal/` или встроенную knowledge base.

## 8. Граница первого среза

Не входят:

- универсальный taint engine или полный call graph;
- моделирование missing-call advisory;
- анализ deployment-документации и runtime-конфигурации;
- пересчёт severity, SLA, CVSS или priority;
- генерация исправлений и commits;
- LLM verdict или LLM evidence;
- новые специально подобранные real-dependency кейсы ради увеличения
  метрики.

Следующее направление выбирается после первого среза по реальным
неразрешённым mandatory conditions: deployment facts, guards/config,
missing-call или opaque dependency dispatch.

## 9. Done-критерий

Срез завершён, когда:

1. выполнены требования модели и evidence из §5–6;
2. проходят все регрессии §7.1;
3. выполнен real-dependency acceptance §7.2;
4. `gofmt`, `go vet ./...`, `go test ./...` проходят;
5. live corpus проходит с `false-safe=0`;
6. в production-коде нет case-specific идентификаторов или семантики;
7. `eval/README.md` описывает новый результат и оставшиеся границы.

Если целевые negative-кейсы достигаются только специальными правилами
для yaml/protobuf либо coverage нельзя показать в отчёте, срез не принят.

## 10. Шлюз дальнейшей разработки

Прохождение done-критерия доказывает, что анализатор способен выдать
результат поверх reachable-сигнала на нескольких реальных dependency.
Оно ещё не доказывает частоту такого результата в произвольном потоке
тикетов.

До просмотра результатов владелец продукта фиксирует закрытую выборку
исторических тикетов, baseline `govulncheck` и правила учёта результата.
Алгоритм не настраивается по отдельным кейсам этой выборки до завершения
оценки.

Проверка отдельно отвечает на два вопроса:

1. **Переносимость:** доля заранее выбранных `reachable`/`package-level`
   сигналов, для которых анализатор дал принятое product-specific
   доказательство сверх baseline;
2. **Практическая экономия:** активное время ручного решения с отчётом и
   без него. Чтобы один и тот же тикет не был уже изучен, используются
   разные reviewers либо заранее разделённые сопоставимые группы.

Один удачный закрытый тикет доказывает только возможность переноса. Он не
доказывает частоту пользы или экономию времени и сам по себе не является
основанием расширять статический анализ.

- если все выигрыши остаются только в созданных для eval мини-продуктах,
  дальнейшее усложнение статического анализатора приостанавливается;
- если закрытая выборка показывает повторяемую дополнительную ценность,
  можно выбирать следующий mandatory condition;
- если перенос блокируется повторяющимся видом недостающего evidence,
  следующий срез выбирается именно по этому классу, а не по удобному
  демонстрационному примеру.

Закрытая проверка не является условием прохождения open-source CI, но
является условием продуктового решения продолжать расширение анализатора.

## 11. Последующие гипотезы ценности

Эта спецификация не утверждает, что только safe verdict приносит пользу.
После первого среза отдельно специфицируются:

- доказательное `EXPLOITABLE` поверх reachability: attacker origin,
  exposure, guards и остальные mandatory conditions;
- использование deployment/config/documentation evidence для разрешения
  условий и обоснованного изменения risk priority;
- LLM risk/SLA proposal как неавторитетная рекомендация поверх
  детерминистических фактов;
- remediation workflow после уже доказанного verdict.

Каждое направление должно называть результат, отсутствующий у
standalone `govulncheck`, и способ быстро проверить его на существующем
корпусе или закрытых продуктовых кейсах.
