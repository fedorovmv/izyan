# Negative-check coverage: build-tag + interface dispatch — план фичи (gap-analysis кандидат #4)

Статус: done. Закрывает пункты 3.3 и 3.4 `docs/dev/current/gap-analysis.md`.

## Проблема

`Verifier.VerifyFalse` подтверждает FALSE-кандидатов через `SearchSymbol`
(нет ссылок на subject) + `ScanDynamic` (func_value/linkname/reflect).
Две системные дыры остаются незакрытыми:

1. **Build-tag-вариативность.** `ix.pkgs` содержит только файлы,
   удовлетворяющие `ix.Build.BuildTags`. Файл `//go:build special`,
   вызывающий subject, невидим для `SearchSymbol` → VERIFIED FALSE на
   пути, который компилируется при другом наборе тегов. Спека (§19)
   явно требует проверять «build-tagged implementation».
2. **Interface dispatch.** Для субъекта `Type.Method` вызов `x.Method()`
   где `x` — интерфейсный тип резолвится `types.Selection` на *интерфейс*,
   а не на `Type` → `selObjMatch` его не считает. Конкретный impl,
   удовлетворяющий интерфейсу, — стандартный обход статического «нет
   вызовов» (живой пример: `URI.String` через `fmt.Stringer`).

## Дизайн

Обе проверки — **расширение скоупа NV, только ослабляют VERIFIED**:
находки переводят статус в `INSUFFICIENT_SCOPE` (FALSE-claim остаётся,
но вердикт и ревьюер на него не опираются — существующая семантика).
Никогда не усиливают FALSE.

### `Index.GatedRefs(ctx, ref) ([]domain.CallSite, error)`

- Источник: `pkg.IgnoredFiles` (уже в `NeedFiles`-mode) — файлы,
  исключённые build constraints; `_test.go` пропускаются.
- Синтаксический матч без type info (файл не типизирован): файл должен
  импортировать `ref.Package`; дальше —
  - `pkgAlias.Name` / `pkgAlias.Type` селекторы → site;
  - для `Type.Method`-субъектов — `x.Method` селекторы только если файл
    ссылается на `pkgAlias.Type` (иначе `.Close()` по чужому интерфейсу
    даёт шум).
- Парсинг в общий `ix.fset` — позиции валидны для evidence.

### `Index.InterfaceDispatchSites(ctx, ref) ([]domain.CallSite, error)`

- Только для `Type.Method`-субъектов: резолвит `*types.Named` T в
  dep-пакете (product pkgs → `loadExtra` fallback).
- В product packages ищет `x.Method` с `Selections` kind `MethodVal`,
  где `Recv()` — интерфейс I, и `types.Implements(T, I)` или
  `types.Implements(*T, I)` → site.
- Не мэтчит: интерфейс сам объявлен в dep (его метод — сам субъект),
  concrete recv (SearchSymbol их уже видит).

### Wiring

В `VerifyFalse` стратегия-диспетч оборачивается пост-проверкой
`extendNegativeScope`: только когда стратегия вернула `VERIFIED`,
прогоняются оба сканера по всем subjects; находки →
`INSUFFICIENT_SCOPE` + evidence ID'ы + notes:

- `N reference(s) in files excluded by current build tags`
- `N interface-dispatched call site(s) may reach subject`

`CONTRADICTED` не используется — эти находки показывают *незакрытый
скоуп*, а не доказанный путь (tag-файл может быть мёртвым кодом,
interface-dispatch не доказывает конкретный impl).

## Файлы

| Файл | Что |
|---|---|
| `internal/goanalysis/coverage.go` (new) | `GatedRefs`, `InterfaceDispatchSites`, helpers |
| `internal/goanalysis/negative.go` | `extendNegativeScope` + реструктура dispatch в `VerifyFalse` |
| `testdata/gatedprod/` | `main.go` + `special.go` (`//go:build special`, зовёт `vuln.Parse`) |
| `testdata/ifaceprod/` | `var s fmt.Stringer = u; s.String()` по `URI.String` |
| `coverage_test.go` | gated ref находится; iface dispatch находится; отсутствие шума |
| `negative_test.go` | VERIFIED→INSUFFICIENT_SCOPE при gated/dispatch находках |

## Тесты / DoD

- gatedprod: `GatedRefs` возвращает сайт из tag-файла; без tag-файла — 0.
- ifaceprod: `InterfaceDispatchSites` находит `s.String()`; для субъекта
  без интерфейсной реализации — 0.
- VerifyFalse: fixture-кейс VERIFIED→INSUFFICIENT_SCOPE.
- Регрессия: живой кейс GHSA-465g (`URI.String` диспатчится через
  `fmt.Stringer` в продукт-референс?) — смотрим, не ушёл ли VERIFIED
  FALSE в INSUFFICIENT_SCOPE ложно. Если ушёл — это корректное
  ослабление (реальный скоуп-пробел), фиксируем.
- `go vet`, `go build`, `go test ./...`, `-race`.

## Не входит

- Резолв impl'ов интерфейсов, вызываемых *внутри* dep-кода;
- перечисление всех реализаций интерфейса без привязки к subject;
- запуск билда под альтернативными тегами (обнаружение факта
  существования пути, не его компилируемость);
- `configuration overrides` (§19) — частично закрыто C-EXPOSURE.
