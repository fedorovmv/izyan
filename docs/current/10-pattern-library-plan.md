# План: Exploit Pattern Library (кандидат №1 gap-analysis)

## Зачем

Сейчас `exploit.Builder` строит один generic-набор условий для любой
уязвимости: `C-REACH` (достижим sink) + `C-INPUT` (атакующий контролирует
аргумент). Это работает для input→sink vulns (4 из 6 RabbitMQ-кейсов),
но ломается на других классах:

- `GHSA-27gv` (PlainAuth хранит креды в exported полях `Connection.Config.SASL`)
  — обязательное условие тут «кто-то может прочитать объект», а не
  «input управляем». Generic-модель → INCONCLUSIVE.
- `GHSA-465g` (`URI.String` → `ParseURI` round-trip затирает конфиг) —
  обязательное условие «продукт делает пару вызовов round-trip», а не
  «input к sink». Generic-модель → INCONCLUSIVE.

Спека §9 предусматривает Pattern Library: шаблоны вопросов по классам
уязвимостей, а не готовые вердикты. Реализуем её.

## Принцип

Pattern = декларативное правило: «для этого класса уязвимости
обязательные условия — вот такие», каждое мапится на существующий
`ConditionKind` и evaluator. Pattern не решает verdict — он задаёт,
**что именно проверять**. Неизвестный класс → текущая generic-модель
(обратная совместимость, fallback всегда существует).

## Архитектура

```text
Vulnerability (CWE + summary + description + fix-diff)
  -> Classify()                     // CWE-мапа → keyword fallback
  -> Registry.Lookup(class)         // pattern
  -> pattern.Instantiate(subjects)  // mandatory + supporting conditions
  -> merge с generic C-REACH/C-INPUT, если pattern их не покрывает
  -> ExploitModel{Class: class}
```

### Новые файлы

| Файл | Содержимое |
|---|---|
| `internal/exploit/classify.go` | `Classify(v Vulnerability, patch *fix.Patch) Class` — CWE-приоритет, keyword-regex fallback, `ClassUnknown` default |
| `internal/exploit/patterns.go` | `Class`, `Pattern`, `ConditionTmpl`, `Registry` (builtin), `Instantiate` |
| `domain` | `ExploitModel.Class string` + `Condition.Params map[string]string` (pattern-специфичные параметры для evaluator'ов: bound, api-pair, ...) |

### Классификация

Источник сигнала по приоритету:

1. `v.CWE` — авторитетно. Мапа ~15 CWE → класс:
   `CWE-119/787/125`→`OOB_WRITE`, `CWE-190`→`INTEGER_OVERFLOW`,
   `CWE-400/770`→`RESOURCE_EXHAUSTION`, `CWE-476/252`→`NIL_DEREF`,
   `CWE-22/23/36`→`PATH_TRAVERSAL`, `CWE-78/89/90/94`→`INJECTION`,
   `CWE-502`→`DESERIALIZATION`, `CWE-200/522/256/319`→`INFO_LEAK`,
   `CWE-441/918`→`SSRF`, `CWE-287/306/863`→`AUTH_BYPASS`,
   `CWE-611`→`XXE`, `CWE-1333/407`→`REDOS`, `CWE-362`→`RACE`.
2. Keyword regex на `Summary+Details` — fallback при пустом CWE:
   `frame|packet|parser|desync`→`WIRE_PARSER`, `credential|password|secret|plaintext`→`INFO_LEAK`, `uri|url|query.*param`→`URI_CONFUSION`, `panic|dos|denial|exhaust|oom`→`RESOURCE_EXHAUSTION`, `traversal|outside.*root`→`PATH_TRAVERSAL`, и т.д.
3. `ClassUnknown` — generic модель.

## Стартовые паттерны (4, покрывают живые кейсы)

### 1. `WIRE_PARSER` / `OOB_WRITE` / `INTEGER_OVERFLOW` / `RESOURCE_EXHAUSTION` (peer-driven transport/parsers)

Mandatory:

- `C-REACH` — SYMBOL_REACHABLE по sinks (как сейчас).
- `C-PEER-INPUT` — ATTACKER_CONTROL, subjects=sinks,
  param `input_source=peer` (разрешает ServerTransportInput/client-правило
  даже когда описание условия не содержит remote-слов — param важнее regex).
- `C-CONSTRAINT` — INPUT_CONSTRAINT: ограничение из advisory
  (например «length > INT32_MAX»). Param `bound` заполняет LLM или
  остаётся generic — evaluator `Validation` ищет guard в vendored source
  до sink; guard отсутствует в уязвимой версии → TRUE.

Supporting: `C-ENTRY` (listener/dial entrypoint — риск-приоритет).

Закрывает: 4 текущих EXPLOITABLE amqp-кейса — та же логика, но
условия становятся явнее.

### 2. `INFO_LEAK` (credential/secret exposure в структурах)

Mandatory:

- `C-DATA-PRESENT` — CONFIGURATION: структура с чувствительными
  exported-полями реально существует и используется. Evaluator:
  `FindSymbol` подтверждает тип/поле в dep source → TRUE
  (детерминистическая проверка, уже есть).
- `C-EXPOSED` — SYMBOL_REACHABLE с param `direction=read`:
  есть ли читатели поля вне владельца — `SearchSymbol`/`FindCallers`
  по имени поля/геттера в продукте и в пакетах-зависимостях.
  Найден reader → TRUE; не найден + scope covered → FALSE-кандидат → NV.

Supporting: `C-USE` — продукт использует API, который инициализирует
структуру (module usage, уже есть).

Закрывает: `GHSA-27gv`. Модель станет «retention есть + читатель есть»
вместо мимо-цели «input управляем».

### 3. `URI_CONFUSION` / `CONFIG_INJECTION` (round-trip)

Mandatory:

- `C-ROUNDTRIP` — SYMBOL_REACHABLE param `sequence=mod.FuncA->mod.FuncB`:
  продукт вызывает **пару** API, образующую уязвимый цикл
  (`URI.String` + `ParseURI`). Evaluator: проверка пары в
  `ModuleUsage.Callee` — дешёвое детерминистическое условие на
  уже собранных данных.
- `C-INPUT` — ATTACKER_CONTROL на источник вредного значения
  (TLS-path, query params): обычный `ArgumentOrigin`.

Закрывает: `GHSA-465g`. Round-trip пара проверяется по 44 callees —
если продукт не вызывает `URI.String`, условие честно FALSE-кандидат.

### 4. `NIL_DEREF` / panic-DoS (простой стартовый)

Mandatory:

- `C-REACH` — как обычно.
- `C-TRIGGER` — INPUT_CONSTRAINT: данные, вызывающие nil/panic,
  достижимы через peer-input (существующий `ServerTransportInput`).
- `C-HOT-PATH` — supporting: sink на hot-path соединения
  (chain через `ModuleInternalReach` к listen/read-loop).

## Condition.Params — как паттерны общаются с evaluator'ами

```go
type Condition struct {
    // ...существующие поля...
    Params map[string]string `json:"params,omitempty"`
}
```

Параметры:

- `input_source=peer|arg|config` — ServerTransportInput: `peer`
  разрешает транспортное правило без regex на описании.
- `direction=read` — SymbolReachable: ищем читателей поля, не путь к sink.
- `sequence=a->b` — SymbolReachable: пара API из ModuleUsage callees.
- `bound=<expr>` — INPUT_CONSTRAINT: конкретное guard-условие для
  `Validation` evaluator'а (лениво: пока текст, семантика позже).

Неизвестные params игнорируются — паттерн остаётся declarative.

## Изменения по файлам

1. `internal/domain/domain.go`: `ExploitModel.Class`, `Condition.Params`.
2. `internal/exploit/classify.go` (+тест): CWE map + keyword fallback.
3. `internal/exploit/patterns.go` (+тест): Registry + 4 паттерна + Instantiate.
4. `internal/exploit/builder.go`: `Classify` → pattern merge → `m.Class`.
   Unknown → прежняя модель. Params пробрасываются.
5. `internal/llm/exploit.go`: merge — LLM-условия дополняют pattern set,
   валидация kind/subjects не меняется; LLM может заполнять `Params["bound"]`.
6. `internal/evaluator`: 
   - `SymbolReachable` — ветки `direction=read`, `sequence=`.
   - `ServerTransportInput` — `input_source=peer` param вместо/рядом regex.
7. `internal/states`: проброс fix-patch summary в Classify при наличии
   (сигнал класса), без новых tool calls.
8. `internal/report`: секция exploit model показывает `Class`.
9. Тесты: classify (CWE→class, keywords, unknown), instantiate (amqp-advisory
   → правильный набор), round-trip FALSE при отсутствии пары,
   read-direction для PlainAuth-поля.
10. Доки: `08-how-it-works` (pattern layer), `09-gap-analysis` (закрыт пункт 1).

## Definition of done

- `GHSA-27gv`: модель `INFO_LEAK` — C-DATA-PRESENT TRUE (PlainAuth
  exported поля в vendor), C-EXPOSED UNKNOWN/FALSE по SearchSymbol.
  Вердикт всё ещё INCONCLUSIVE, но **по правильному условию** — это и
  есть успех: честное «недоказано наличие читателя», а не «не смогли
  смоделировать».
- `GHSA-465g`: `C-ROUNDTRIP` — проверка пары `URI.String`+`ParseURI`
  в callees → честный FALSE-кандидат → NV.
- 4 wire-parser кейса: вердикты не меняются (regression: EXPLOITABLE
  остаётся), но claims показывают C-PEER-INPUT/C-CONSTRAINT.
- Generic fallback: synthetic advisory без CWE/keywords → старая модель.
- `go test ./...` зелёный, включая новые unit + e2e кейс на фикстуре.

## Ограничения MVP паттернов

- `bound` в C-CONSTRAINT — сначала текстовая аннотация для отчёта и
  LLM-подсказка; семантическая проверка guard («доказать `len>=N`»)
  — следующий кандидат, не этот.
- Классификация по CWE важнее keywords: где они расходятся — limitation
  «class inferred by keywords, CWE absent».
- Паттерны живут в коде, не в YAML/DB — 4 штуки не оправдывают
  конфигурационного слоя; устойчивый формат появится когда их станет >10.
