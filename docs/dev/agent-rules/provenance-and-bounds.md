# Provenance, argument tracing и numeric bounds

Читать перед работой в `internal/goanalysis/` и
`internal/evaluator/provenance.go`.

## Tracing

- `DataFlow.Arg` — индекс sink-аргумента (-1 = не аргументный); guard
  records тоже несут `Arg`; покрытие проверяется per-arg.
- Константы/GENERATED bounded по определению: пропускаются в coverage,
  но `DataFlow.Value` проверяется на удовлетворение `params.bound`
  (константа-нарушение → deterministic TRUE, до guard-пути).
- Sanitize-switch range-gated форма: cases сравнивают `cv`, присваивают
  `ident=T(cv)`; bounded только при двусторонней границе `cv` +
  обязательный default.
- `&x.field` address-taken → field-guard покрытие отклоняется:
  pointer-alias пишет мимо write-site скана.

## Dependency scope (vendor-internal provenance)

- Dep-пакеты кешируются в `Index.extraPkgs` (общий fset с продуктом).
  `FindDepCallers` сканирует syntax пакета subject'а — unexported
  dep-субъект имеет call sites только внутри dep.
- Scope скана — по владеющему пакету (`callerScope`/`memberScope`):
  enclosing-функция/поле из dep → dep+product скан; product →
  product-only. Не смешивай scope'ы — product callers dep-функции
  не вызывают напрямую.
- `types.Object` identity между разными `packages.Load` — только
  `types.Object.Id()` (`sameObject`); pointer-сравнение даёт ложные
  промахи на dep-пакетах.
- Composite literal мерджит origins элементов — `&io.LimitedReader{R: r}`
  это origin `r`, а не CONSTANT.
- Populate-семейства (единый сканер): out-param `&v`, slice-populate
  (`io.ReadFull`, `x.Read(b)`), receiver-mutation (`v.Write`,
  `WriteString`, `ReadFrom`) — все пишут origin источника/аргумента
  в dst/receiver.
- Peer-источники: `net.Dial*`/`tls.Dial*`/`Accept` →
  `EXTERNAL_UNTRUSTED`; `Read` на сетевых receiver'ах — тоже.
  Interface dispatch внутри dep (`m.read(r)`) не резолвится →
  честный UNKNOWN, эвристика unexported+peer-driven остаётся fallback.
- Dep-FALSE: `verifyInputFalse` перетрейсит те же dep-сайты
  (`FindDepCallers`), не product-callers; неразрешённый трейс →
  INSUFFICIENT_SCOPE, никогда не FALSE. `ServerTransportInput`:
  resolved flows → `ArgumentOrigin` (trace побеждает эвристику);
  flows пусто/все UNKNOWN → эвристика.

## Numeric bounds

- `Validation.BoundLow/BoundHigh` — вкл. enforce'нутый диапазон;
  nil = неограниченность, НИКОГДА не подставляй 0 за неразрешённый
  порог. Union по write-site'ам: lo=min, hi=max, отсутствие стороны =
  unbounded.
- `boundsDirection` нормализует в surviving range: `v < K` → выживает
  `v >= K`; `v <= K` → `v >= K+1`; `v > K` → `v <= K`; `v >= K` →
  `v <= K-1`. `exprIntValue`: literal, named const, `T(lit)`-конверсии.
- `params.bound` — дизъюнкты `var op lit`; связь var→arg позиционно +
  по имени в `guard.Property` (name-match снимает arg-фильтр). FALSE +
  «bound verified» — только при численном контрадикторе каждого
  дизъюнкта; нераспарсенные термы → limitation, не буст.

Тесты-образцы: `internal/evaluator/provenance_bound_test.go`,
`internal/goanalysis/source_test.go` (фикстуры `testdata/*prod`).
