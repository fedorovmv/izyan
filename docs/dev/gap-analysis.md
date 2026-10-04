# Gap analysis: спеки vs реализация

Сопоставление [`specs/governing-spec.md`](specs/governing-spec.md), [`specs/analyzer-agent-spec.md`](specs/analyzer-agent-spec.md),
[`goals-scope.md`](../goals-scope.md), [`history/features/mvp-implementation-plan.md`](history/features/mvp-implementation-plan.md), [`decisions/architecture-decisions.md`](decisions/architecture-decisions.md)
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
| Proof validation | Machine proposals о необходимости условия/полноте локусов не имеют отдельного проверяемого proof gate; B30 остаётся expert-basis веткой | → B32 |
| Критичность и обоснование | Exposure/supporting facts не образуют законченной контекстной оценки с policy | → B33 |
| Missing-call model | Детерминированная проверка пропущенных проверок (missing-call): модель should-call для методов валидации на активных пайплайнах (напр., jwt-go `VerifyAudience` на конвейере `MapClaims.Valid`); доказательство пропуска (`EV-MISSING-CALL`) разрешает `C-REACH`, `C-OMISSION`, `C-INPUT`, `C-LOCUS` в TRUE | закрыто |
| Parsers & config | Compile-time константный payload (`FalsifierConstantOrGeneratedInput`) изолирован от рефлексии целевых структур в парсерах (`yaml`, `protojson`); чтение локальных конфигураций (`os.ReadFile`) подтверждается как доверенная среда (`FalsifierTrustedInfrastructure`); `eval` оптимизирован (параллелизация `-j`, `--case`, исключение дублирования govulncheck) | закрыто |
| Release checkout | Автоматическое разрешение тегов/веток релизов из тикетов и параметров (`--checkout-release`, `--release` / `--git-ref`) и безопасный изолированный анализ в git worktree без мутации рабочей копии разработчика | закрыто |
| Dep-internal opaque dispatch | Статическое разрешение функциональных полей и method values в struct-field/package-var/local колбэках (`funcFields`, `packageVars`, `funcEdges`, `resolveMethodValue`) в `moduleEdges` и reachability-анализе; разрешение внутренней цепочки диспетчеризации фильтров и транспорта gRPC xDS (`real-micro-xds` -> EXPLOITABLE, baseline corpus 100% resolved, 0 inconclusive) | закрыто |

## 2. Открытый бэклог (приоритетный, с done-критериями)

Бэклог упорядочен по принципу «какой UNKNOWN закрывает» — приоритет
получает работа, уменьшающая число неопределённых claims. Закрытые
пункты здесь не хранятся: история изменений — в `git log`, планах
[`history/features/`](history/features/) и роадмапах [`roadmaps/`](roadmaps/), текущая механика — в
[`analysis-internals.md`](analysis-internals.md). Закрытие пункта =
удаление строки из бэклога в том же коммите, что закрывает работу.

Критерий MVP: модуль даёт больше `govulncheck` и выдаёт доказательно
обоснованные вердикты. Приоритет P0 блокирует критерий.

### P1 — e2e-качество

| # | Пункт | Зачем | Done-критерий |
|---|-------|-------|----------------|
| B26 | Явный контракт полноты sink set и доказательство nonpayload-входов (остаток) | `AffectedSymbols` остаётся `KNOWN_ONLY`; отсутствие найденного пути от ingress item не доказывает его нерелевантность при внешнем вводе | Константный ingress для `real-protojson-const` доказан и закрыт в NEPF через изоляцию константного payload и нулепараметрических методов парсера. Остаток: persisted advisory-scoped completeness artifact с vulnerability/module/version/mandatory-condition binding и evidence IDs для случаев с внешним/недоказанным вводом; регрессионные контрпримеры и live corpus false-safe=0 |
| B29 | Независимая доказательная база дополнительной пользы | Cleared-rate и совпадение с собственной разметкой не доказывают преимущество над govulncheck; module-only finding не является package-level сигналом; единственный package-level cleared — unix-stat — уже имеет no-call результат govulncheck | Source/build audit отрицательных результатов, парные положительные и adversarial controls, независимая разметка; отдельно измерять новые доказанные отклонения при reachable-сигнале и экономию triage, не считать повторение no-call результата доказанной добавленной пользой |
| B32 | Независимая валидация necessity/completeness и применения основания | Проверка отсутствия пакета не доказывает правильность выбранного L; существующий evidence ID и согласие LLM не подтверждают proposition | [Спека §9](specs/llm-cve-analysis-spec.md), [роадмап Tasks 7–9](roadmaps/llm-cve-analysis-roadmap.md): immutable proof input, binding/scope/rule checks и replay; unsupported necessity остаётся OPEN; автономное сужение модели только после отдельного capability gate без NonLocusBasis; XDS/rename/incomplete-series/second-mechanism controls; до gate нет замены действующей экспертной границы B30 |
| B33 | Контекстная критичность и приоритет исправления | Достижимость не задаёт consequences/exposure/priority; supporting factors пока не вычисляют обоснованную оценку для deployment | [Спека §12](specs/llm-cve-analysis-spec.md), [роадмап Task 11](roadmaps/llm-cve-analysis-roadmap.md): baseline severity/source отдельно от verdict, проверенные impact/exposure/guards, versioned supplied policy, ASSESSED/PROVISIONAL/UNASSESSED, no-policy/no-override/unknown-safe поведение, policy/deployment invalidation и §13 rationale; ни низкий риск, ни SLA не меняют safe-verdict |
| B27 | LLM-assisted локальное основание отклонения (исследование) | Проверить дополнительную ценность поверх govulncheck без расширения production-анализатора; [спецификация](specs/llm-dismissal-research-spec.md), [роадмап](roadmaps/llm-dismissal-research-roadmap.md) | Четыре jose2go-контроля (`[]byte`, `string`, callback, deployment-dependent key), source audit necessity/coverage, воспроизводимые тесты и свежий govulncheck baseline; deterministic/LLM результаты либо явно NOT_RUN; досье с итогом «checker / эксперт / гипотеза опровергнута», без подмены ручного audit машинным VERIFIED и без изменения прежних expect |
| B30 | Exploit model: defect-locus / mode-gate mandatory-условия | Реализован контракт отрицательного доказательства (spec §8): `C-LOCUS` условие с subjects=ровно множеству дефектных локусов L; falsifiers: `locus-package-absent` (все пакеты L вне `go list -deps` графа EV-PACKAGE-LIST) и `locus-function-unreached` (пакеты в сборке, но функции дефектного локуса доказанно не вызываются продуктом или зависимостями, а динамические маркеры чисты); negative verification — перепроверка absence по build-graph evidence и глубокая проверка достижимости функций дефектного локуса с проверкой инкапсуляции (`internal/` пакетов); NEPF с `UnresolvedSubjects` допустим только когда все unresolved ∈ L. В `ingressScan` реализована изоляция рефлексии декодеров: reflective value operations по целевой структуре (out) не создают блокирующих UnknownCall для константного входного payload (in). **Замыкание necessity — консервативное:** L = advisory-declared set минус записанные экспертные решения `NonLocusBasis` (символ+основание+authority, persisted в модели и отчёте); автоматическое исключение из L запрещено — текстовое несовпадение fix/body-скана трактуется как «соответствие не установлено», не как чистое тело (review-контрпример: переименование `mdata`→`headers` давало ложный VERIFIED NEPF — закрыто). Machine anchors (guarded-site / enabler-candidate / fix-changed / not-fix-changed) — аннотации для эксперта, не исключения; модуль порождает `ProposedNonLocus` — draft-исключения с записанным наблюдением, не участвующие в вердикте до экспертного подтверждения через `non_locus` (через `--non-locus-basis` или флаг `--accept-locus-proposals`); отчёт печатает блок «Машинная оценка» — предлагаемая оценка (МОЖНО ОТКЛОНИТЬ / ПОСЛЕ ПОДТВЕРЖДЕНИЯ / ТРЕБУЕТСЯ ПРОВЕРКА (УСЛОВНО)), per-symbol статус пакетов и требуемые экспертные решения (включая override guarded-site флага) + допущения вне машинной проверки (полнота declared set, истинность basis, build-контекст); эксперт отвечает на advisory-level вопрос без аудита кода продукта; решение для символа вне declared set игнорируется с limitation. Операнды из тестовых файлов и стандартные переменные ошибок (`err`) фильтруются. Отсутствие fix-diff (fetch-ошибка, advisory без фикса) не снимает `C-LOCUS` — L = declared set − basis сохраняется, теряются только аннотации/proposals (flake TLS-timeout на PR9365 молча снимал гейт и игнорировал basis — закрыто). Falsifier дополнительно требует покрытия build-вариантов: продуктовые файлы, исключённые записанным build-контекстом (//go:build, GOOS/GOARCH, cgo), но импортирующие пакет локуса, переводят verification в INSUFFICIENT_SCOPE → UNKNOWN (контроль `gated-scope`). Итоговый раздел отчёта и вывод CLI `analyze` формируют готовое для трекера задач обоснование на русском языке (Tracker-ready rationale) с полным контекстом проверки, подтверждением версии, фактами о сборке и остаточными рисками. Нейтральный пул corpus-real: `real-micro-plain-6443` (без basis → EXPLOITABLE: declared символ в трейсе → C-LOCUS TRUE), `real-micro-plain-6443x` (с basis → NEPF), `real-micro-xds-6443` (mode-on → EXPLOITABLE), `real-micro-wrap-6443` (factory → EXPLOITABLE), `real-micro-pkg-6443` (pkg в графе, но функция не вызывается → NEPF через `locus-function-unreached`), `real-yaml-const`, `real-yaml3-const`, `real-protojson-const` (константный payload → NEPF), `real-yaml-file` (trusted infrastructure config → NEPF). Boundary-контроли на testdata/locuslib: неполная fix series (непропатченный сайт остаётся в L → falsifier не покрывает → INCONCLUSIVE), rename (текстовое несовпадение не снимает обязательство), два независимых дефекта (partial package coverage → UNKNOWN), upstream-only fix (сайт не в diff → остаётся в L → INCONCLUSIVE). Открыто: сайт вне advisory declared set контракту невидим; корректность экспертных исключений — вне машины (verification фиксирует их наличие в limitations); regex-парсинг hunk'ов охватывает `len(x)==0`/`x==nil`; второй независимый advisory для переносимости не найден |

### P2 — глубина покрытия

| # | Пункт | Done-критерий |
|---|-------|----------------|
| B5 | Build-tag варианты в dep-коде | Snapshot фиксирует tag-set; claims помечаются при tag-зависимом покрытии; компилируемость tag-варианта проверяется, не только синтаксический импорт |
| B6 | Config-gated reachability | Config-gates влияют на гарды (учтено); reachability-config — нет → conditional-reachability метка в claim; связывание `var:`/`field:` bind-источников с config-значениями; различение `0.0.0.0`/`127.0.0.1` на уровне условия, не только supporting-scope |
| B7 | `AUTHENTICATION_CONDITION` per-route | Route→handler→middleware маппинг; TRUE только при покрытии конкретного handler'а |
| B8 | Bound-семантика шире | `len(x)`, `x != 0`, float, арифметика в термах; юнит-тесты каждой формы |
| B15 | Reviewer: patch-misinterpretation + scope-mismatch | §21 требует проверок, которые Structural не делает: «условие описывает не тот класс, что патч», «claim вне скоупа advisory» → детерминистический чек или semantic-review правило + тест; live 6c5v/GO-2026-6372: fix-subjects `openTune`/`pick` не связывают peer-controlled `recvContent` payload с условием, xwwf: peer tune value не доказан через opaque `pick`; truth EXPLOITABLE, допустимый результат INCONCLUSIVE до независимого доказательства payload, без args-only fallback |
| B17 | LLM advisory-контур (D16) | Параллельная оценка семантики + verdict estimate, репортируемая отдельно от авторитетного контура | `llm_assessment.json` + `## LLM assessment` в report.md; расхождение с вердиктом → finding; unit-тест: advisory не меняет claims; e2e: кейс с divergence; спека: [`roadmaps/llm-advisory-roadmap.md`](roadmaps/llm-advisory-roadmap.md) |
| B16 | LLM semantic-гипотезы для KB | Opaque/unresolvable callee → UNKNOWN навсегда; LLM может подсказать семантику вызова | Гипотеза «f читает env/file» в GAP_ANALYSIS → детерминистический трейс внутрь тела ищет заявленный примитив; evidence с меткой llm-suggested/code-verified; draft-записи в `knowledge_suggestions` отчёта (мерж только через `--knowledge`, никогда не авто); тест: REJECTED-гипотеза не трогает claim |
| B14 | Build/test результат не влияет на claims | `actBuildTest` пишет BUILD/TEST evidence, но build failure — caveat, не демоция claim; покрытие пути тестами не оценивается → per-vulnerability test-coverage факт или claim-оговорка |
| B9 | Паттерны вне 4 семейств | По живым кейсам; каждый паттерн = registry entry + фикстура |
| B18 | Snapshot/toolchain-факты как platform conditions | `go_version` продукта и тулчейн-семантика (TLS 1.2 floor с go1.22+ и т.п.) не моделируются → 33mj истина NEPF, анализатор INCONCLUSIVE. Done: platform-condition claim решается по snapshot `go_version` + тест; 33mj-кейс даёт NEPF |
| B19 | Точность reflect/unsafe демоций NV | Демоция по маркеру не проверяет, что write-site реально достигает типа субъекта (465g: `amqp091.URI` никогда не создаётся продуктом → истина NEPF, анализатор INCONCLUSIVE). Done: маркер учитывает достижимость типа/поля; 465g-кейс даёт NEPF |
| B20 | Root-cause верификация теряет fix-added символы | `Verifier.Verify` ищет кандидата только в dep-версии продукта (`FindSymbol` → product-scope); символ, добавленный патчем, там отсутствует по определению → в Alternatives. 27gv: LLM верно предложил `PlainAuth.String`/`setSASL`/`Reconnect` — существуют в v1.13.0 (это и есть фикс), но отброшены | Двойная верификация: vuln-версия (exploit-субъект) + fix-diff/fixed source (root-cause идентичность, метка «added by fix»); кейс с аддитивным фиксом сохраняет fix-side кандидата в RootCauses; регресс-тест на 27gv-сценарий |
| B25 | Вызовы между вложенными модулями | `ModuleUsage` атрибутирует callee по реальному модулю; вызов API nested-модуля не доказывает использование родителя, но может вызвать его транзитивно и поэтому блокирует FALSE-кандидат. Done: проверять рёбра child→parent по полному import/call graph; тесты с таким ребром и без него; UNKNOWN при неполном графе, без false-safe |

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
`github.com/fedorovmv/izyan`), репозиторий продукта задаётся через
`VA_PRODUCT_REPO` (env) или `--repo`, проверка — `go test ./...` +
`go run ./cmd/izyan eval --corpus eval/live-corpus.json`.

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
