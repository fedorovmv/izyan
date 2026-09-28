# Gap analysis: спеки vs реализация

Сопоставление [`dev/specs/governing-spec.md`](../specs/governing-spec.md), [`dev/specs/analyzer-agent-spec.md`](../specs/analyzer-agent-spec.md),
[`goals-scope.md`](../../goals-scope.md), [`dev/plans/mvp-implementation-plan.md`](../plans/mvp-implementation-plan.md), [`dev/decisions/architecture-decisions.md`](../decisions/architecture-decisions.md)
с кодом по состоянию на HEAD. Содержит только пробелы и бэклог.

## 1. Открытые пробелы (спека↔код)

Что реализовано — [`analysis-internals.md`](analysis-internals.md) и
[`implementation-status.md`](implementation-status.md); здесь только
пробелы. Механика подробностей — в internals; actionable-работа — в §2.

| Область | Пробел | Статус |
|---|---|---|
| Exploit model | Паттернов 4 семейства; PATH_TRAVERSAL/INJECTION/SSRF/AUTH_BYPASS/XXE/REDOS/RACE/DESERIALIZATION — на generic-модели; keyword-классификация score-эвристика (limitation) | → B9 |
| Condition kinds | `AUTHENTICATION_CONDITION` по дизайну не FALSE (per-route/gateway/deployment проверки вне скана) — только TRUE при покрытии wiring | → B7 |
| Data origins | `EXTERNAL_AUTHENTICATED` различён для outbound, inbound — deployment-hint не per-route доказательство → B7; детекция DB-драйверов по pkg path — эвристика; reflect/pointer-записи в поля невидимы скану → B11 | → B7, B11 |
| Transformations | Семантика трансформов не моделируется: opaque call → UNKNOWN (честно, но закрывает claim'ы) | limitation, не бэклог |
| Negative check | Конфигурация, меняющая reachability (не гарды) — в резерве | → B6 |
| Reviewer | «patch misinterpretation» и «scope mismatch» из §21 не проверяются — Structural ловит только структурные дефекты | → B15 |

## 2. Открытый бэклог (приоритетный, с done-критериями)

Бэклог упорядочен по принципу «какой UNKNOWN закрывает» — приоритет
получает работа, уменьшающая число неопределённых claims. Закрытые
пункты здесь не хранятся: история изменений — в `git log` и планах
[`dev/plans/`](../plans/), текущая механика — в
[`analysis-internals.md`](analysis-internals.md). Закрытие пункта =
удаление строки из бэклога в том же коммите, что закрывает работу.

Критерий MVP: модуль даёт больше `govulncheck` и выдаёт доказательно
обоснованные вердикты. Приоритет P0 блокирует критерий.

### P0 — блокирует критерий

| # | Пункт | Зачем | Done-критерий |
|---|-------|-------|----------------|
| B1 | **Ground-truth разметка live-корпуса** | `expect` пиннит наблюдаемое поведение — `false-safe=0` это отсутствие регрессий, не доказательство правильности | Истинный вердикт каждого из 11 кейсов зафиксирован вручную по advisory+коду; `expect` сравнивает с истиной; метод разметки описан в [`eval/README.md`](../../../eval/README.md) |

### P1 — e2e-качество

| # | Пункт | Зачем | Done-критерий |
|---|-------|-------|----------------|
| B4 | Устойчивость repair к bogus-демоциям | LLM-ревьюер дважды демотировал VERIFIED-FALSE семантическим misread («противоречит root cause»); промпт дополнен, но защита нужна детерминистическая | Демоция VERIFIED-FALSE требует ссылки на конкретный артефакт (маркер/uncovered site/traced origin); тест на bogus-demotion |
| B13 | **Расширение корпуса доказательной базы** | Live-слой узок: 11 кейсов, 1 dep, 1 класс; нет сравнительной базы vs standalone govulncheck | ≥30 кейсов суммарно (≥4 класса, ≥3 реальных dep) через generated-manifest продукты `eval/products/` без committed уязвимых манифестов; baseline-таблица govulncheck-vs-analyzer в [`eval/README.md`](../../../eval/README.md); ground-truth файл на каждый позитивный вердикт; `false_safe=0`; план: [`dev/plans/corpus-expansion-plan.md`](../plans/corpus-expansion-plan.md) |

### P2 — глубина покрытия

| # | Пункт | Done-критерий |
|---|-------|----------------|
| B5 | Build-tag варианты в dep-коде | Snapshot фиксирует tag-set; claims помечаются при tag-зависимом покрытии; компилируемость tag-варианта проверяется, не только синтаксический импорт |
| B6 | Config-gated reachability | Config-gates влияют на гарды (учтено); reachability-config — нет → conditional-reachability метка в claim; связывание `var:`/`field:` bind-источников с config-значениями; различение `0.0.0.0`/`127.0.0.1` на уровне условия, не только supporting-scope |
| B7 | `AUTHENTICATION_CONDITION` per-route | Route→handler→middleware маппинг; TRUE только при покрытии конкретного handler'а |
| B8 | Bound-семантика шире | `len(x)`, `x != 0`, float, арифметика в термах; юнит-тесты каждой формы |
| B15 | Reviewer: patch-misinterpretation + scope-mismatch | §21 требует проверок, которые Structural не делает: «условие описывает не тот класс, что патч», «claim вне скоупа advisory» → детерминистический чек или semantic-review правило + тест |
| B17 | LLM advisory-контур (D16) | Параллельная оценка семантики + verdict estimate, репортируемая отдельно от авторитетного контура | `llm_assessment.json` + `## LLM assessment` в report.md; расхождение с вердиктом → finding; unit-тест: advisory не меняет claims; e2e: кейс с divergence |
| B16 | LLM semantic-гипотезы для KB | Opaque/unresolvable callee → UNKNOWN навсегда; LLM может подсказать семантику вызова | Гипотеза «f читает env/file» в GAP_ANALYSIS → детерминистический трейс внутрь тела ищет заявленный примитив; evidence с меткой llm-suggested/code-verified; draft-записи в `knowledge_suggestions` отчёта (мерж только через `--knowledge`, никогда не авто); тест: REJECTED-гипотеза не трогает claim |
| B14 | Build/test результат не влияет на claims | `actBuildTest` пишет BUILD/TEST evidence, но build failure — caveat, не демоция claim; покрытие пути тестами не оценивается → per-vulnerability test-coverage факт или claim-оговорка |
| B9 | Паттерны вне 4 семейств | По живым кейсам; каждый паттерн = registry entry + фикстура |

### P3 — deferred by design

| # | Пункт | Почему |
|---|-------|--------|
| B10 | Сетевые адаптеры трекеров | `--ticket` generic JSON покрывает intake |
| B11 | goroutine/channel dispatch, interface-impl внутри dep-кода, глубокие generated-цепи | Терминальные ограничения синтаксического скана |

Процесс: пункт берётся сверху вниз; закрытие — только с done-критерием
(тест/живой кейс), после чего строка удаляется из §2 в коммите
закрытия; история — в `git log`, не в этом файле. Новые находки
добавляются с приоритетом, не висят в разговоре.

### Handoff notes (что читать/трогать новой сессией)

Самодостаточные задачи — можно делегировать субагенту или свежей
сессии. Общий контекст: репо плоский (`internal/` на корне, модуля
`example.com/vuln-analyzer`), репозиторий продукта задаётся через
`VA_PRODUCT_REPO` (env) или `--repo`, проверка — `go test ./...` +
`go run ./cmd/analyzer eval --corpus eval/live-corpus.json`.

- **Корпус-дрейф**: `ghsa-j497-x9hr-x34x` на продукт-референсе даёт
  INCONCLUSIVE вместо pinned EXPLOITABLE (C-PEER-INPUT UNKNOWN). Причина
  — не B12: проверено stash-прогоном; похоже, dep-scope flows (B3)
  стали резолвиться в CONSTANT → `hasResolvedFlows` гейтит transport-
  эвристику в `evaluator/transport.go`. Либо баг гейта (CONSTANT не
  должен считаться «resolved» для peer-input), либо corpus re-pin —
  решение за B1 ground-truth.
- **B4** (делегируемо): `internal/states/states.go` — repair demotes
  high-findings; `internal/goanalysis/negative.go` — VERIFIED статусы.
  Правило: demotion VERIFIED-FALSE требует `required_check`/`problem`
  со ссылкой на артефакт (marker `reflect_write`/`unsafe_*`/uncovered
  site/origin) — иначе finding понижается до advisory. Тест —
  `internal/states/` bogus-demotion case.
- **B8** (делегируемо): `internal/evaluator/provenance.go` —
  `parseBound`/`boundTerm.satisfies`/`falsifiedBy`;
  `internal/goanalysis/provenance.go` — `exprIntValue`,
  `boundsDirection`. Расширять по одной форме: `len(x)`, `x != 0`,
  float. Тесты — `provenance_bound_test.go` образец.
- **B1** (полу-делегируемо): драфт разметки можно поручить — agent
  читает advisory (`eval/live-corpus.json` ids) + evidence продукта и
  предлагает true-verdict с rationale, но финальная разметка — за
  человеком (это и есть ценность пункта).
