# Ground truth live-корпуса (B1)

Ручная разметка истинного вердикта каждого кейса `live-corpus.json`.
Продукт: продукт-референс (`${VA_PRODUCT_REPO}`, коммит `996b4c44`),
amqp091-go `v1.10.0` (vendored), toolchain `go1.26.1`.

## Метод

Для каждого кейса, вручную:

1. Прочитать advisory (`eval/advisories/live/*.json`): механизм,
   направление данных (read-path / write-path / config), триггер.
2. Найти уязвимый код в vendored dep v1.10.0 и подтвердить, что фикс
   отсутствует в снапшоте.
3. Проследить использование dep API продуктом (`components/amqp09/`):
   какие вызовы есть, кто поставляет аргументы (config / message meta /
   константы), есть ли безусловный путь peer→sink.
4. Свериться с persisted evidence последнего прогона (claims, data
   flows, ModuleReachable, govulncheck findings).
5. Вердикт по правилам спеки §20: `EXPLOITABLE` требует доказанных
   mandatory-условий; безопасный вердикт — фальсификатора обязательного
   условия; недоказанное в обе стороны → `INCONCLUSIVE`. Источник peer-
   ввода при config-зависимой маршрутизации — не доказан и не
   опровергнут → `INCONCLUSIVE`.

Threat-модель: брокер может быть враждебным/MITM (продукт поддерживает
`amqp.Dial` без TLS — `helper.go:77`). Deployment-условия (auth,
доступность listener'а) фиксируются limitation'ом, а не частью вердикта.

`expect` в корпусе = истинный вердикт; `INCONCLUSIVE` дополнительно
допускается там, где истина — определённый вердикт, а механизм его
доказательства ещё не реализован (помечено «консервативно приемлемо»).

## Таблица истины

| Кейс | Класс | Истина | Прогон (до B1) | Вердикт о выводе |
|---|---|---|---|---|
| GHSA-4v58 | RESOURCE_EXHAUSTION (`readField` 'x' len<0 → panic) | EXPLOITABLE | EXPLOITABLE | корректно |
| GHSA-c5pq | WIRE_PARSER (`readLongstr` desync) | EXPLOITABLE | EXPLOITABLE | корректно |
| GHSA-r9c8 | RESOURCE_EXHAUSTION (`recvContent` make(0, header.Size)) | EXPLOITABLE | EXPLOITABLE | корректно |
| GHSA-xwwf | RESOURCE_EXHAUSTION (`openTune` frame_max без floor) | EXPLOITABLE | EXPLOITABLE | корректно |
| GHSA-6c5v | RESOURCE_EXHAUSTION (oversized body > frame_max) | **EXPLOITABLE** | NO_EXPLOIT_PATH_FOUND | **FALSE-SAFE** → см. дефект D1 |
| GO-2026-6372 | то же (alias 6c5v) | **EXPLOITABLE** | NO_EXPLOIT_PATH_FOUND | **FALSE-SAFE** → D1 |
| GHSA-rm6m | RESOURCE_EXHAUSTION (`Qos` signed→unsigned) | NO_EXPLOIT_PATH_FOUND | NO_EXPLOIT_PATH_FOUND | корректно (bound-гарды [0,1024]/[0,1GiB] на всех write-site'ах; аргументы из config) |
| GHSA-27gv | INFO_LEAK (`Config.SASL` PlainAuth plaintext) | INCONCLUSIVE | INCONCLUSIVE | корректно (creds retained — TRUE; reader не найден статически, dynamic-читатели не исключаемы) |
| GHSA-465g | URI_CONFUSION (`URI.String`→`ParseURI` round-trip) | **NO_EXPLOIT_PATH_FOUND** | INCONCLUSIVE | консервативно приемлемо (вериф. FALSE демотирован reflect-маркером; см. обоснование) |
| GHSA-33mj | TLS MinVersion в `tlsConfigFromURI` | **NO_EXPLOIT_PATH_FOUND** | INCONCLUSIVE | консервативно приемлемо (snapshot go1.26 → implicit floor TLS1.2; нужен PLATFORM_CONDITION по go_version) |
| GHSA-j497 | INTEGER_OVERFLOW (shortstr uint8 trunc) | **INCONCLUSIVE** | INCONCLUSIVE | корректно — re-pin с EXPLOITABLE, см. обоснование |

## Обоснования

### GHSA-6c5v / GO-2026-6372 → EXPLOITABLE (было NO_EXPLOIT_PATH_FOUND)

Уязвимый код — `Channel.recvContent`: v1.10.0 `channel.go:452`
`ch.body = make([]byte, 0, ch.header.Size)` — `header.Size` (uint64)
контролируется брокером через content-header. Продукт вызывает
`Channel.Consume` (`reader.go:445`), каждая доставка проходит
`recvContent` → hostile broker → OOM. Подтверждено govulncheck-трейсом
`Consume` и цепочкой `Dial*→open→openTune` в `ModuleReachable`.

Дефект **D1 (false-safe)**: `GovulncheckCoverage="covered"` через
vulndb-листинг, но entry `GO-2026-6372` не объявляет affected symbols —
govulncheck эмитит только package-level findings (трейсы кончаются на
`Dial`/`Consume`/`Qos`), которые по построению не могут заматчиться с
root-cause символами. `SymbolReachable` трактовал отсутствие совпадения
кадров как «no call path» → FALSE-кандидат → NV VERIFIED (нет product-
refs на unexported `openTune`/`pick` — верно, но беспредметно:
доказательства вообще не было). Исправлено: FALSE по молчанию
govulncheck допустим, только когда все субъекты объявлены в
`AffectedSymbols`; `ModuleReachable`-цепочка — позитивное TRUE-
доказательство до FALSE-ветки.

Дополнительно: advisory fix-ref (`6beb7b51`, PR #353) — это фикс
frame-min negotiation (`openTune`/`pick`→`negotiateFrameSize`), а
фактический cap `headerSize≤FrameSize` в `recvContent` пришёл в v1.13.0
другим изменением — root cause по fix-diff формально корректен, но
неполон. Вердикт это не меняет: `openTune` тоже исполняется на каждом
`Dial`.

### GHSA-j497 → INCONCLUSIVE (re-pin с EXPLOITABLE)

Sink `writeFrame`/`writeShortstr` — исходящая сериализация; вход в
shortstr-поля идёт из: config-строк (queue/exchange/key/consumerTag),
goel-выражений `pd.*`/`exchange`/`key`, вычисляемых над сообщением, и
meta→`amqp.Table` ключей (гейтится `exclude_filter`, nil → копии нет).
Безусловного peer→shortstr пути >255 байт в коде продукта нет:
wire-shortstr поля входящего `Delivery` ограничены 255 байтами протокола,
meta-ключи от брокерских header-ключей тоже ≤255. Путь существует только
через конфигурацию (выражение может спроецировать longstr-значение
заголовка в shortstr-поле) → mandatory `C-PEER-INPUT` ни доказать, ни
опровергнуть по снапшоту → INCONCLUSIVE. Дрейф до INCONCLUSIVE (dep-flows
резолвятся в CONSTANT → `hasResolvedFlows` гейтит transport-эвристику)
случайно совпал с истиной: heuristic-TRUE для write-sink был
over-approximation'ом. Остаётся вопрос: CONSTANT-ориджин не должен был
«отвечать» на peer-input вопрос — см. D2.

### GHSA-465g → NO_EXPLOIT_PATH_FOUND (прогон: INCONCLUSIVE)

Round-trip требует `amqp091.URI.String()` + `ParseURI`. Продукт
обращается с URL через `net/url` (`helper.go` getUrls/`u.String()`),
`amqp091.URI` нигде не создаёт — значения типа URI в продукте не
существует, reflect-диспатч `URI.String` без инстанса невозможен.
Верифицированный FALSE на неполной паре верен; демоция ревьюером по
общему reflect-маркеру — консервативно приемлемое отклонение (B4).

### GHSA-33mj → NO_EXPLOIT_PATH_FOUND (прогон: INCONCLUSIVE)

`tlsConfigFromURI` без `MinVersion` — слабость реализуется только на
toolchain <1.18; снапшот go1.26.1 → неявный floor TLS 1.2 → брокер не
может понизить протокол. Условие «слабый TLS negotiated» опровергается
фактом снапшота (PLATFORM_CONDITION по `go_version`). Анализатор такой
проверки для этого класса не имеет → INCONCLUSIVE консервативно верно.

### GHSA-27gv → INCONCLUSIVE

`PlainAuth{Username,Password}` plaintext в `Connection.Config.SASL`
(connection.go:984) — данные присутствуют (TRUE). Читателя в продукте
нет (`Config.SASL` не референсится; `%+v`/сериализация Connection не
встречается), но исключить reflect/heap-читателей статически нельзя →
терминальный UNKNOWN → INCONCLUSIVE.

### GHSA-rm6m → NO_EXPLOIT_PATH_FOUND

Документированный кейс (см. раздел ниже): оба аргумента `Qos` идут из
конфига через mapstructure-теги и клампятся bound-гардами на всех
write-site'ах ([0,1024], [0,1GiB]); bound-дизъюнкты контрадиктят → FALSE
VERIFIED. INCONCLUSIVE допускается из-за недетерминизма LLM-ревью.

### GHSA-4v58 / c5pq / r9c8 / xwwf → EXPLOITABLE

Read-path/negotiation уязвимости: `readField`, `readLongstr`,
`recvContent`, `openTune` исполняются в peer-driven read path на каждом
кадре/коннекте; продукт вызывает `Dial`+`Consume` (govulncheck-трейсы +
module usage). Hostile broker — threat-модель корпуса. Root cause
подтверждён fix-diff evidence во всех четырёх.

## Найденные дефекты

- **D1 (P0, исправлен вместе с B1)**: `covered`-классификация через
  vulndb-листинг + отсутствие affected symbols → govulncheck не мог
  оценить reachability, а молчание превращалось в VERIFIED FALSE.
  Два живых false-safe вердикта (6c5v, GO-2026-6372).
- **D2 (P2, backlog)**: `hasResolvedFlows` считает «resolved» любой
  origin включая CONSTANT — для peer-input условий константный аргумент
  не отвечает на вопрос о wire-байтах. Для j497 результат совпал с
  истиной случайно; на read-path sink'ах CONSTANT-ориджин может подавить
  transport-эвристику → консервативный UNKNOWN (потеря качества, не
  false-safe).
- **D3 (P2, backlog)**: классификатор 33mj пометил TLS-MinVersion как
  INFO_LEAK → модель задаёт нерелевантные условия. Истина требует
  PLATFORM_CONDITION по `go_version` (floor TLS1.2 с Go 1.18).
- **D4 (P2, backlog)**: reflect-демоция VERIFIED-FALSE не проверяет,
  существует ли в продукте значение целевого типа (465g: `amqp091.URI`
  нигде не конструируется — reflect нечего диспатчить).
