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
| Exploit model | «Missing-call» advisory (уязвимость — отсутствие вызова валидации, jwt-go GO-2020-0017): dep-invocation гейт блокирует false-safe NEPF → INCONCLUSIVE, но should-call семантики в модели нет — условие «валидация обязана выполняться» не выводится | → B21 |

## 2. Открытый бэклог (приоритетный, с done-критериями)

Бэклог упорядочен по принципу «какой UNKNOWN закрывает» — приоритет
получает работа, уменьшающая число неопределённых claims. Закрытые
пункты здесь не хранятся: история изменений — в `git log` и планах
[`dev/plans/`](../plans/), текущая механика — в
[`analysis-internals.md`](analysis-internals.md). Закрытие пункта =
удаление строки из бэклога в том же коммите, что закрывает работу.

Критерий MVP: модуль даёт больше `govulncheck` и выдаёт доказательно
обоснованные вердикты. Приоритет P0 блокирует критерий.

### P1 — e2e-качество

| # | Пункт | Зачем | Done-критерий |
|---|-------|-------|----------------|
| B26 | Явный контракт полноты sink set и доказательство nonpayload-входов | `AffectedSymbols` остаётся `KNOWN_ONLY`; отсутствие найденного пути от ingress item не доказывает его нерелевантность | Persisted advisory-scoped completeness artifact с vulnerability/module/version/mandatory-condition binding и evidence IDs, проверенный до sink closure; отдельное положительное доказательство nonpayload вместо фильтра по пустому `Reaches`; `real-protojson-const` получает NEPF только с этим основанием либо с полностью безопасным ingress closure; регрессионные контрпримеры и live corpus false-safe=0 |
| B29 | Независимая доказательная база дополнительной пользы | Cleared-rate и совпадение с собственной разметкой не доказывают преимущество над govulncheck; module-only finding не является package-level сигналом; единственный package-level cleared — unix-stat — уже имеет no-call результат govulncheck | Source/build audit отрицательных результатов, парные положительные и adversarial controls, независимая разметка; отдельно измерять новые доказанные отклонения при reachable-сигнале и экономию triage, не считать повторение no-call результата доказанной добавленной пользой |
| B27 | LLM-assisted локальное основание отклонения (исследование) | Проверить дополнительную ценность поверх govulncheck без расширения production-анализатора; [спецификация](../specs/llm-dismissal-research-spec.md), [план](../plans/llm-dismissal-research-plan.md) | Четыре jose2go-контроля (`[]byte`, `string`, callback, deployment-dependent key), source audit necessity/coverage, воспроизводимые тесты и свежий govulncheck baseline; deterministic/LLM результаты либо явно NOT_RUN; досье с итогом «checker / эксперт / гипотеза опровергнута», без подмены ручного audit машинным VERIFIED и без изменения прежних expect |
| B30 | Exploit model: defect-locus / mode-gate mandatory-условия | Реализован контракт отрицательного доказательства (spec §8): `C-LOCUS` условие с subjects=ровно множеству дефектных локусов L; falsifier `locus-package-absent` — все пакеты L вне `go list -deps` графа (EV-PACKAGE-LIST), package-present-but-unreached → UNKNOWN; negative verification — перепроверка absence по build-graph evidence; NEPF с `UnresolvedSubjects` допустим только когда все unresolved ∈ L. **Замыкание necessity — консервативное:** L = advisory-declared set минус записанные экспертные решения `NonLocusBasis` (символ+основание+authority, persisted в модели и отчёте); автоматическое исключение из L запрещено — текстовое несовпадение fix/body-скана трактуется как «соответствие не установлено», не как чистое тело (review-контрпример: переименование `mdata`→`headers` давало ложный VERIFIED NEPF — закрыто). Machine anchors (guarded-site / enabler-candidate / fix-changed / not-fix-changed) — аннотации для эксперта, не исключения; модуль порождает `ProposedNonLocus` — draft-исключения с записанным наблюдением, не участвующие в вердикте до экспертного подтверждения через `non_locus`; решение для символа вне declared set игнорируется с limitation. Нейтральный пул corpus-real: `real-micro-plain-6443` (без basis → EXPLOITABLE: declared символ в трейсе → C-LOCUS TRUE), `real-micro-plain-6443x` (с basis → NEPF), `real-micro-xds-6443` (mode-on → EXPLOITABLE), `real-micro-wrap-6443` (factory → EXPLOITABLE), `real-micro-pkg-6443` (pkg в графе → INCONCLUSIVE). Boundary-контроли на testdata/locuslib: неполная fix series (непропатченный сайт остаётся в L → falsifier не покрывает → INCONCLUSIVE), rename (текстовое несовпадение не снимает обязательство), два независимых дефекта (partial package coverage → UNKNOWN), upstream-only fix (сайт не в diff → остаётся в L → INCONCLUSIVE). Открыто: сайт вне advisory declared set контракту невидим; корректность экспертных исключений — вне машины (verification фиксирует их наличие в limitations); regex-парсинг hunk'ов охватывает `len(x)==0`/`x==nil`; второй независимый advisory для переносимости не найден |

### P2 — глубина покрытия

| # | Пункт | Done-критерий |
|---|-------|----------------|
| B5 | Build-tag варианты в dep-коде | Snapshot фиксирует tag-set; claims помечаются при tag-зависимом покрытии; компилируемость tag-варианта проверяется, не только синтаксический импорт |
| B6 | Config-gated reachability | Config-gates влияют на гарды (учтено); reachability-config — нет → conditional-reachability метка в claim; связывание `var:`/`field:` bind-источников с config-значениями; различение `0.0.0.0`/`127.0.0.1` на уровне условия, не только supporting-scope |
| B7 | `AUTHENTICATION_CONDITION` per-route | Route→handler→middleware маппинг; TRUE только при покрытии конкретного handler'а |
| B8 | Bound-семантика шире | `len(x)`, `x != 0`, float, арифметика в термах; юнит-тесты каждой формы |
| B15 | Reviewer: patch-misinterpretation + scope-mismatch | §21 требует проверок, которые Structural не делает: «условие описывает не тот класс, что патч», «claim вне скоупа advisory» → детерминистический чек или semantic-review правило + тест; live 6c5v/GO-2026-6372: fix-subjects `openTune`/`pick` не связывают peer-controlled `recvContent` payload с условием, xwwf: peer tune value не доказан через opaque `pick`; truth EXPLOITABLE, допустимый результат INCONCLUSIVE до независимого доказательства payload, без args-only fallback |
| B17 | LLM advisory-контур (D16) | Параллельная оценка семантики + verdict estimate, репортируемая отдельно от авторитетного контура | `llm_assessment.json` + `## LLM assessment` в report.md; расхождение с вердиктом → finding; unit-тест: advisory не меняет claims; e2e: кейс с divergence; спека: [`dev/plans/llm-advisory-plan.md`](../plans/llm-advisory-plan.md) |
| B16 | LLM semantic-гипотезы для KB | Opaque/unresolvable callee → UNKNOWN навсегда; LLM может подсказать семантику вызова | Гипотеза «f читает env/file» в GAP_ANALYSIS → детерминистический трейс внутрь тела ищет заявленный примитив; evidence с меткой llm-suggested/code-verified; draft-записи в `knowledge_suggestions` отчёта (мерж только через `--knowledge`, никогда не авто); тест: REJECTED-гипотеза не трогает claim |
| B14 | Build/test результат не влияет на claims | `actBuildTest` пишет BUILD/TEST evidence, но build failure — caveat, не демоция claim; покрытие пути тестами не оценивается → per-vulnerability test-coverage факт или claim-оговорка |
| B9 | Паттерны вне 4 семейств | По живым кейсам; каждый паттерн = registry entry + фикстура |
| B18 | Snapshot/toolchain-факты как platform conditions | `go_version` продукта и тулчейн-семантика (TLS 1.2 floor с go1.22+ и т.п.) не моделируются → 33mj истина NEPF, анализатор INCONCLUSIVE. Done: platform-condition claim решается по snapshot `go_version` + тест; 33mj-кейс даёт NEPF |
| B19 | Точность reflect/unsafe демоций NV | Демоция по маркеру не проверяет, что write-site реально достигает типа субъекта (465g: `amqp091.URI` никогда не создаётся продуктом → истина NEPF, анализатор INCONCLUSIVE). Done: маркер учитывает достижимость типа/поля; 465g-кейс даёт NEPF |
| B20 | Root-cause верификация теряет fix-added символы | `Verifier.Verify` ищет кандидата только в dep-версии продукта (`FindSymbol` → product-scope); символ, добавленный патчем, там отсутствует по определению → в Alternatives. 27gv: LLM верно предложил `PlainAuth.String`/`setSASL`/`Reconnect` — существуют в v1.13.0 (это и есть фикс), но отброшены | Двойная верификация: vuln-версия (exploit-субъект) + fix-diff/fixed source (root-cause идентичность, метка «added by fix»); кейс с аддитивным фиксом сохраняет fix-side кандидата в RootCauses; регресс-тест на 27gv-сценарий |
| B21 | Missing-call модель (остаток) | False-safe закрыт гейтом: `DepInvocationState`+`checkDepInvocation` — мёртвый субъект + живой sibling-пайплайн → INSUFFICIENT_SCOPE (real-jwt-auth → INCONCLUSIVE). Остаток: модель «should-call» не представлена — условие «валидация обязана выполняться на пути» не выводится из advisory, поэтому missing-call кейс навсегда INCONCLUSIVE, а не EXPLOITABLE/NEPF | Условие `should-call`: receiver-пайплайн доказанно жив И субъект доказанно не вызывается внутри него (все вызовы enclosing-цепочки просмотрены) → mandatory-условие TRUE (дефект подтверждён), а не только блок NEPF; регресс-e2e: jwt-auth → EXPLOITABLE с named evidence |
| B24 | Dep-internal opaque dispatch (function-регистрации, watcher/goroutine-ребра) | grpc xds: sink `rbac.builder.ParseFilterConfig` достигается через `httpfilter.Register(builder{})` (запись в registry — вызов функции, не map-literal) + watcher-колбэки из pump-горутины xdsclient → govulncheck даёт только package-level, наш moduleEdges тоже обрывается; real-micro-xds истина EXPLOITABLE, анализатор INCONCLUSIVE. Соседний дефект (vacuous «zero product refs» для internal/unexported субъектов) исправлен — гейт `productReferenceable` в negative.go | Рёбра через registry-регистраторы вида `pkg.Register(v)` и watcher-callback интерфейсы в dep-графе, либо честный `incomplete-scope` evidence-гейт; e2e: real-micro-xds не INCONCLUSIVE-молчит, а несёт точный limitation «registry/callback dispatch unproven» или резолвится |
| B25 | Вызовы между вложенными модулями | `ModuleUsage` атрибутирует callee по реальному модулю; вызов API nested-модуля не доказывает использование родителя, но может вызвать его транзитивно и поэтому блокирует FALSE-кандидат. Done: проверять рёбра child→parent по полному import/call graph; тесты с таким ребром и без него; UNKNOWN при неполном графе, без false-safe |
| B28 | Общий бюджет closure query и повторные dependency loads | Per-position expression budget и post-load eviction не ограничивают весь запрос: caller/function-value индексы могут повторно загружать пакеты и инвалидировать кэши; `real-ssh-slowpesh` завершается, но занимает около 15 минут | Deadline запроса распространяется на packages.Load; общий бюджет package/AST работы покрывает enumeration и index scans; исчерпание сохраняет blocker и Complete=false, без отрицательного вывода; regression на повторные loads и свежие corpus/performance замеры |

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

- **B1 закрыт** (выполнено): истина 11 кейсов — `eval/ground-truth.md`;
  `expect` пиннит истину. Разметка поймала два false-safe (6c5v,
  GO-2026-6372 → NEPF): исправлено — covered+silence FALSE теперь
  требует всех субъектов в `AffectedSymbols`, `ModuleReachable`-цепочка
  — позитивное TRUE-доказательство до FALSE-ветки. j497: истина
  INCONCLUSIVE (peer→shortstr config-contingent) → re-pin.
- **B8** (делегируемо): `internal/evaluator/provenance.go` —
  `parseBound`/`boundTerm.satisfies`/`falsifiedBy`;
  `internal/goanalysis/provenance.go` — `exprIntValue`,
  `boundsDirection`. Расширять по одной форме: `len(x)`, `x != 0`,
  float. Тесты — `provenance_bound_test.go` образец.
