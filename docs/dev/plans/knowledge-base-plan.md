# Knowledge-base: семантика экосистемы как данные, не код

Бэклог: [`dev/current/gap-analysis.md`](../current/gap-analysis.md) §5 B12.

## Проблема

Трейсер provenance и exposure опираются на таблицы семантики Go-
экосистемы: какие функции производят какой origin (`os.Getenv` →
CONFIGURATION), через какие вызовы данные протекают
(`io.Copy(w,r)` → origin arg1 в arg0), где адрес у listener-примитивов.
Это не кейс-специфичный хардкод — ни одна запись не называет код
продукта; это универсальная база знаний (аналог CodeQL Models-as-Data /
gosec rule sets).

Но таблицы захардкожены в коде — новый config-декодер (koanf,
cleanenv), RPC-фреймворк или IO-API требует правки `provenance.go` и
пересборки. Расширение должно быть данными.

Направление ошибки — консервативное: пропуск записи → UNKNOWN
(безопасно), неверная запись → неверный origin (опасно) → внешняя база
только аддитивна и валидируется.

## Текущие таблицы (полный реестр)

`internal/goanalysis/provenance.go`:

- `knownSourceFuncs` — `pkg.Func` → `DataOrigin` (os.Getenv, flag.*,
  net/http.Get, encoding/json.Unmarshal, …)
- `passthroughFuncs` — `pkg.Func` → индекс arg, чей origin несёт
  результат (io.ReadAll, decoders, readers, url.Parse)
- `passthroughMethods` — имена методов-accessor'ов (Text/Bytes/String)
- `slicePopulateFuncs` — `pkg.Func` → (dst, src) (io.ReadFull,
  binary.Read, io.Copy)
- `readIntoMethods` — Read/ReadAt (arg0 = destination)
- `recvMutateMethods` — Write/WriteString/ReadFrom (receiver
  accumulator)
- `configTagKeys` — mapstructure/env/envconfig/toml/ini
- `authCallNames` — имена callee, привязывающие credentials
- `isServiceCall` — подстрока импорта `google.golang.org/grpc`
- `httpClientOrigin` — спец-кейс `net/http` (pkg-funcs vs methods,
  endpoint arg0)

`internal/goanalysis/exposure.go`:

- `listenAddrArg` — listener-примитивы → индекс address-аргумента
  (-1 = адрес вне вызова)

## Этап 1 — консолидация (zero behavior change)

1. `internal/goanalysis/knowledge.go`:

```go
type Knowledge struct {
    SourceFuncs       map[string]domain.DataOrigin
    PassthroughFuncs  map[string]int
    PassthroughMethods map[string]bool
    SlicePopulateFuncs map[string][2]int
    ReadIntoMethods   map[string]bool
    RecvMutateMethods map[string]bool
    ConfigTagKeys     []string
    AuthCallNames     map[string]bool
    ListenAddrArg     map[string]int
    ServiceCallPkgHints []string   // import-path substrings → RPC stubs
    HTTPClientPkgs    map[string]bool // "net/http" etc.
}
func DefaultKnowledge() *Knowledge
```

2. `Index` получает `KB *Knowledge` + ленивый `ix.kb()` (nil →
   `DefaultKnowledge()`).
3. Механическая замена `knownSourceFuncs[k]` → `ix.kb().SourceFuncs[k]`
   во всех call-site'ах (все — методы `*Index`, проверено).
4. `isServiceCall`/`httpClientOrigin` параметризуются полями KB.

Критерий: suite зелёный без изменений поведения; таблицы не видны
снаружи пакета (unexported доступ через ix.kb()).

## Этап 2 — внешнее расширение

5. `KnowledgeFile` JSON-схема — зеркало полей
   (`source_funcs: {"os.Getenv":"CONFIGURATION"}`,
   `passthrough_funcs: {"x.Y":0}`, `config_tag_keys: ["koanf"]`, …);
   origin-строки валидируются против enum `DataOrigin`.
6. `LoadKnowledge(path)` — **только аддитивный мерж**: неизвестный ключ
   JSON → error; ключ, уже существующий в таблице, → error (явное >
   тихое переопределение). Ошибки — понятные, с именем ключа.
7. CLI `--knowledge <path>` на analyze/eval/scan → merge в `Index.KB`
   при построении (см. `cmd/analyzer` где строится srcIndex;
   scan/eval — общий путь через options).

Критерий: юнит-тест — JSON-расширение `source_funcs` меняет origin на
фикстуре; тесты на unknown key/conflict/invalid origin → error.

## Этап 3 — правило и доки

8. [`agent-rules/generality.md`](../../agent-rules/generality.md) (новый файл): никаких
   case/product-идентификаторов в коде; KB — только универсальная
   семантика экосистемных API; направление ошибки консервативно;
   расширение — сначала через JSON, новые дефолты только для широко
   стабильных API; строка в индексе AGENTS.md.
9. [`dev/current/gap-analysis.md`](../current/gap-analysis.md) — B12 → §4 с коммитом; [`eval/README.md`](../../../eval/README.md) — при затронутом
   поведении.

## Открытый вопрос

Автообнаружение `.vuln-analyzer/knowledge.json` в репо продукта vs
только `--knowledge`. Решение по умолчанию: только флаг — явное лучше
магии; чужой репозиторий не должен молча менять семантику анализа.

## Реализовано

`internal/goanalysis/knowledge.go` + `Index.KB` (nil → ленивый
`DefaultKnowledge()`). Дефолты — не Go-литералы, а данные:
`internal/goanalysis/knowledge.json` в схеме `KnowledgeFile`,
вшивается в бинарь через `//go:embed`, `DefaultKnowledge()` парсит его
и мержит в пустую базу — один код-путь для built-in и внешних файлов.
`--knowledge <path>` в `commonFlags` → analyze/scan/eval/remediate;
`vuln-analyzer knowledge` дампит эффективную базу (дефолты или
дефолты+расширение) как шаблон для своего файла и валидирует его.
Мерж аддитивный с same-value-допуском: повтор записи с тем же
значением — no-op (дамп базы можно править и подавать обратно),
переопределение значения — ошибка. Файл версионируется (`"version": 1`,
peek до strict-decode — будущая схема даёт ошибку версии, не unknown
field) и маркируется метаданными: `"language"` — семейство анализатора
(чужой язык → ошибка), `"name"`/`"labels"` — свободные provenance-теги
(builtin/upstream/corp), информационные. Помимо полей плана таблицы покрыли
также `PopulateNames`, `DBPkgs`/`DBPkgHints` и `ListenerPrimitives`
(список `domain.SymbolRef`) — все семантические наборы goanalysis за
KB. Юнит-тест расширения на фикстуре `testdata/kbprod` (origin
UNKNOWN → CONFIGURATION после `source_funcs` записи) +
валидация/конфликты/round-trip дампа — `knowledge_test.go`. Правило —
`docs/agent-rules/generality.md`; поведение по умолчанию не менялось,
`eval/README.md` не тронут.
