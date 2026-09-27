# 20. Live corpus — реальные advisory на реальном репо

## Статус: первый слой реализован

`eval/live-corpus.json` + `eval/advisories/live/*.json` — 11 advisory
`github.com/rabbitmq/amqp091-go` (все фиксированы v1.13.0; продукт на
v1.10.0 → affected по версии) против `продукт-референс`.

## Прогон

```
PATH=$HOME/go/bin:$PATH analyzer eval --corpus eval/live-corpus.json
```

Требования: сеть (root-cause резолвер тянет fix-patch по commit-refs из
advisory) и `govulncheck` в PATH. Без govulncheck reachability идёт через
module-usage fallback — вердикты могут честно смещаться к INCONCLUSIVE.

Результат (детерминистичный прогон, govulncheck v1.1.4):

| Группа | Кейсы |
|---|---|
| EXPLOITABLE | GHSA-4v58, c5pq, j497, r9c8, xwwf — wire-parser класс, peer-driven input, govulncheck-путь до sink |
| NO_EXPLOIT_PATH_FOUND | GHSA-6c5v, GO-2026-6372 — уязвимые символы не вызываются, NV VERIFIED |
| INCONCLUSIVE | GHSA-27gv, 33mj, 465g, rm6m — info-leak/config классы: deploy-dependent условия |

`expect` в корпусе зафиксирован по наблюдаемым вердиктам — это regression
pinned behavior, не независимый ground truth. false-safe=0 остаётся
стоп-критерием.

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

## Следующий слой

- Независимая ручная разметка ground truth (какие из EXPLOITABLE —
  истинно exploitable в проде vs «peer can drive»).
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

После фиксов: arg0 `Qos` теперь трейсится до write-site поля
(`r.prefetchCount = count` в setPrefetchCount), sanitize-switch кламп
(`count<0→0`, `count>1024→1024`) записан Guard=true + Covers — значение,
достигающее sink'а, ограничено на всех write-site'ах. Нерезолвленным
остался только *origin* (config plumbing через reflect) — поэтому
INCONCLUSIVE сохраняется по peer-input, но bound-evidence зафиксирован.
