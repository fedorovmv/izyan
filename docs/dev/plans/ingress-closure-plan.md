# Ingress closure — план фичи (B26)

Статус: in progress. Реализует первый срез
[`dev/specs/incremental-analysis-value-spec.md`](../specs/incremental-analysis-value-spec.md)
— falsifier `constant-or-generated-input` поверх `govulncheck`-сигнала.

## Выбор стратегии

Спека допускает одну из двух стратегий полноты. Реализованы обе:

- **ingress closure** — полный inventory всех входов в reachable
  dependency cone, без обязательной полноты sink set. Доказательство:
  если ни один вход в cone (аргумент/receiver/object state на product
  boundary, callback result, автономный source внутри cone) не может
  нести attacker-данные, то ни один sink в cone их не получит.
- **sink closure** — контракт полноты sink set из advisory
  (`imports[].symbols`): перечисляются все call site'ы заявленных
  sink-символов (product + dep + iface/func-value dispatch), у каждого
  live-сайта payload-позиция (аргумент/receiver/object state по
  `arg_index` условия) трейсится до терминального origin. Любые
  автономные источники вне доказанного payload-flow (напр. `detrand`
  внутри protobuf) closure не блокируют — ingress-семантика остаётся
  строгой и для protojson не закрывается by design.

Правило выбора в evaluator (`closureGate`): FALSE-кандидат выживает,
если верифицирована **либо** ingress closure (complete, все reaching
items safe), **либо** sink closure (complete, все live payload-позиции
не-внешние). Невыполнение обеих → UNKNOWN; записи closure только
ослабляют claim, ничего не доказывая «само по себе отсутствие».

## Модель

`IngressClosure` (domain): per-condition coverage record — module,
complete-флаг, items, blockers.

`IngressItem` — один элемент inventory:

- `boundary_arg` / `boundary_receiver` — аргумент/receiver product→module
  вызова, origin через `classify` (тот же трейсер, что TraceArgument);
- `object_state` — записи `v.F = x`/`v[i] = x` в enclosing функции до
  boundary site (переданный объект читается зависимостью);
- `cone_source` — автономный источник внутри cone: KB source_funcs,
  peer/db/service/http вызовы, package-var с writers, callback dispatch
  вне модуля, channel-receive, cross-module вызовы;
- `intermediate_dep` — product вызов в другой dep-модуль D, у которой
  есть call edge в M (B25-стыковка): доказанного пути нет → UNKNOWN.

## Полнота (complete=false блокирует FALSE)

Blockers:

- escape ссылки на функции модуля вне call-позиции (func values);
- вызовы внутри cone без разрешимого callee (func value, funclit-var);
- `reflect.Value.Call/CallSlice/Method/MethodByName` в cone;
- `plugin`/`unsafe` импорты? — unsafe не вводит новых источников данных и
  не создаёт рёбер; для ingress не блокирует (только weaken var-writer
  доказательств); plugin/linkname → blocker;
- channel-receive (`<-`, `range ch`) в cone → item UNKNOWN (senders вне
  cone не перечислимы);
- `go` в init функциях модуля → item UNKNOWN (вне cone спавн работы);
- package-var read в cone: перечисление writers внутри модуля; escape
  (`&v` вне LHS) → UNKNOWN; origin = merge writes' RHS classify;
- var из другого dep-модуля → UNKNOWN; stdlib var → только KB SourceVars.

Interface dispatch внутри cone: narrowing `dispatchImpls`+instantiated;
impls внутри модуля → edges; вне модуля (product impls) → cone_source
UNKNOWN (callback). Сайт с пустым impl-set → мёртвый вызов, не блокер.

## Поток данных

1. `CollectEvidence.runSourceAnalysis`: для каждой provenance-условия с
   dep-subject'ами → `Source.IngressInventory(module, subjects, hops)` →
   closure в EvidenceGraph + summary evidence.
2. `ArgumentOrigin.Evaluate`: при наличии closure она гейтует FALSE:
   external boundary item с reach до subject → TRUE; deploy-dependent/
   unknown reaching → UNKNOWN; cone_source с небезопасным origin →
   UNKNOWN; complete && все items safe/excluded → FALSE + falsifier.
   Для sink closure: все live-сайты заявленного sink set с non-external
   payload-позициями → FALSE + falsifier. Когда closure-записей нет и
   нет dep-internal flows к поглощению — claim стоит на per-site
   flow-трейсах (VERIFIED решает negative check).
3. `verifyInputFalse`: falsifier == constant-or-generated-input и closure
   есть → пересчёт inventory на verifyHops; воспроизведённый complete
   coverage → VERIFIED; новые blockers/unsafe → INSUFFICIENT_SCOPE;
   external source/reaching boundary → CONTRADICTED. При провале
   ingress-верификации — `verifySink`: повторная энумерация сайтов и
   re-trace payload-позиций на verifyHops=16.

## Границы

- sink closure принимает контракт полноты sink set только из явного
  advisory-списка (`imports[].symbols`); отсутствие декларации →
  closure не вычисляется, гейт не ослабляется;
- mutations внутри контейнеров dep-модуля (карты/struct поля через dep
  API) считаются dep-internal data — boundary inventory покрывает
  product-side регистрации; writes вне модуля не видны → var-правило
  консервативно;
- stdlib вызовы внутри cone классифицируются по KB (source_funcs,
  args_merge_funcs и пр.); незарегистрированные stdlib-источники —
  известная граница KB;
- channel-receive (`<-x`) — origin UNKNOWN (send-сайты не
  инвентаризируются); element-writes (`m[k] = e`, `b[i] ^= e`,
  `x.f = e`) мержат RHS в origin контейнера.

## Память и производительность (go-getter-scale dep-графы)

`real-getter-const` тянет go-getter → aws-sdk/azure/gcp мир (~460
транзитивных пакетов) и был источником серии OOM. Итоговые рубежи:

- `loadMode` без `NeedDeps` и `NeedImports`: retained-пакеты не тащат
  чужие AST и import-stub-деревья; import-граф читается через
  `types.Package.Imports()`;
- `evictExtra` бюджетит по patterns (≤64), пакетам (≤40), файлам
  (≤500) и суммарному transitively-imported types-closure
  (`maxExtraImportClosure`=2500 — каждый retained root держит types-граф
  своего import-замыкания, ~200-400МБ на aws-scale пакет); при эвикции
  очищаются все кэши, удерживающие AST/types-ссылки;
- `txBuf` (записи трансформаций) — dedup + cap: один трейс по
  aws-конусу накапливал миллионы `CallSite` append'ов (2.2GB flat в
  профиле — реальная причина «утечки»);
- `capWhy` на всех границах evaluator (classify / classifyCallEval /
  evalCalleeExpr / cache-stores) и `maxWhyLen`=1024 — строки `why`
  композятся вверх рекурсивно и без кэпа растут экспоненциально;
- `evalBudget`=300k на каждую trace-сессию (per-arg TraceArgument,
  per-position sink closure): fan-out трейса по dep-конусу в принципе
  экспоненциален; исчерпание → UNKNOWN, без unsafe-выводов;
- memguard форсит `debug.FreeOSMemory()` при пересечении бюджета —
  HeapSys иначе учитывает освобождённые, но зарезервированные спаны
  как «удерживаемую» память.

Результат: `real-getter-const` завершается за ~40-80с в ≤1GiB
(INCONCLUSIVE — честно: C-ROUNDTRIP не разрешается), ранее процесс
достигал ~13GiB и убивался watchdog'ом.

## Cross-universe типы и терминированность

Три дефекта, найденных только на real-корпусе после memory-оптимизаций:

- **sameType вместо types.Identical**: один и тот же Go-пакет
  type-check'ится несколько раз (пакет по path-паттерну + по
  `module/...`, re-load после эвикции) — `*types.Named` из разных
  type-checker runs не identical по указателю. Receiver-as-arg0
  fallback в `traceReceiver` сравнивает типы по package path + object
  name с сохранением pointer-глубины (`*T` ≠ `T`). Без этого все
  receiver-позиции `unmarshal(d, m)`-формы падали в UNKNOWN —
  `real-protojson-const` регрессировал до INCONCLUSIVE.
- **callAt self-heal**: сайт, записанный под эвиктнутым load-инстансом,
  не находится в памяти — `callAt` догружает пакет по `file=`-запросу
  и пересканирует. Иначе verify падал на dead fuzz-harness сайтах
  до sink-closure fallback.
- **fvBuildDepth**: `fvParamCallers` не строит чужие func-value
  индексы, будучи вызванным внутри построения (`fvIndex` pass 2) —
  рекурсия `funcCandidates → fvParamCallers → fvIndex` по графу
  пакетов иначе не завершается (real-micro-xds: >30 мин, 6.4GiB →
  145с, ≤1.3GiB). Вложенная недогруженность помечает candidate-set
  open → UNKNOWN, без unsafe-выводов.

Итог корпуса `corpus-real.json` (33 кейса): `real-protojson-const`
→ NO_EXPLOIT_PATH_FOUND, http-пары EXPLOITABLE, getter-const
INCONCLUSIVE, micro-xds честный INCONCLUSIVE за 145с,
`signal-cleared=5/23`, `reachable-cleared=3/17`, `false-safe=0`.
