# Corpus expansion — план фичи (evidence base)

Статус: plan. Закрывает пробел доказательной базы: заявление
«лучше govulncheck» опирается сейчас на 11 live-кейсов одного dep
и одного класса уязвимостей.

## Проблема

- **Live corpus узкий**: 11 advisory, все `amqp091-go`, один продукт
  (`${VA_PRODUCT_REPO}`), по сути один класс (wire parsing). Это
  показывает, что пайплайн работает, но не доказывает общность.
- **Fixture corpus синтетический**: `testdata/` + `example.com/dep`
  проверяют механизмы (provenance, гарды, dynamic-маркеры), но не
  реальный advisory-flow: нет настоящего fix-diff, настоящей DB-записи,
  настоящего dep-кода.
- **Нет сравнительной базы**: ни в одном кейсе не зафиксировано, что
  ответил standalone `govulncheck` — а именно разница «он молчит /
  мы доказуемо отвечаем» и есть ценность продукта.
- **Ограничение**: уязвимые манифесты (`go.mod`/`go.sum`/`vendor` с
  vulnerable requires) коммитить нельзя — Dependabot/OSV-Scanner
  пометят сам репозиторий. Сканеры читают только манифесты; `.go`-
  исходники продукта, advisory JSON и пины внутри corpus JSON им
  невидимы — это даёт безопасную схему ниже.

## Дизайн

### Три слоя корпуса (финальная структура)

| Слой | Где | Что доказывает |
|---|---|---|
| Механизмы | `eval/corpus.json` + `testdata/` | Каждый evaluator/provenance/dynamic-маркер по отдельности |
| Real-dep generated | `eval/corpus-real.json` + `eval/products/` | Реальные advisory + реальный dep-код, разные классы уязвимостей |
| Внешние продукты | env-расширение (`${VA_PRODUCT_REPO}` и др.) | Реальные кодовые базы; снапшоты не коммитятся |

### Generated-manifest продукты (основное нововведение)

`eval/products/<name>/` коммитит **только `.go`-исходники** продукта.
Уязвимый dep резолвится во время прогона:

- `Case` получает поле `deps`: `{"module":"example.com/prod",
  "deps":{"github.com/foo/bar":"v1.2.3"}}` (пины живут в corpus JSON —
  это не манифест, сканерам невидимо).
- Harness: создаёт `eval/.gen/<case-id>/`, копирует туда исходники
  продукта, пишет `go.mod` из полей кейса, `go mod tidy`/`download`
  в GOMODCACHE. `.gen/` в `.gitignore`.
- `go.sum` тоже генерируется в `.gen/` — в репо не попадает.
- Advisory snapshot коммитим в `eval/advisories/real/` (JSON OSV —
  не манифест, безопасно) для воспроизводимости без сети к OSV API;
  `go mod download` требует сети/GOPROXY — документировать, fallback —
  ошибка кейса, не skip.
- Продукт-исходник должен быть **реалистичным** (listener + парсинг +
  типичная бизнес-логика), не case-specific хардкодом — то же правило,
  что для `testdata/`.

### Сравнительная база vs govulncheck

- Новое поле кейса `govulncheck_baseline` (или колонка в отчёте):
  harness прогоняет standalone `govulncheck -mode source <product>`
  и фиксирует исход: `findings` / `silent` / `not-in-db` / `error`.
- `eval/README.md` получает сводную таблицу: кейс → вывод govulncheck →
  наш вердикт → что он не увидел (условие, provenance, NV, config).
  Таблица и есть публичное доказательство дифференциации.

### Ground-truth аннотации

- Каждый live-кейс с позитивным вердиктом получает ручную проверку:
  fix-diff → символ → условия эксплуатации. Хранить кратко в
  `eval/ground-truth/<case-id>.md` (fix-ref, sink, почему вердикт
  корректен, что вручную сверено).
- Нынешние 5/5 EXPLOITABLE с ручной проверкой — формализовать в этих
  файлах (сейчас это только текст в README).

### Отбор кейсов

Цель — ≥30 суммарно, ≥4 класса, ≥3 dep. Критерии отбора advisory:

- класс покрыт pattern library либо расширяет её осмысленно;
- публичный fix-diff с идентифицируемым sink-символом;
- сценарий порождает нетривиальные условия (provenance, config,
  deployment), иначе кейс не добавляет информации сверх govulncheck.

Планируемые классы (кандидаты, финальный список при подборе из Go vuln
DB): wire/parser (есть), path traversal в архивах, SSRF/URL-parse,
DoS/panic в парсерах, TLS/auth-bypass, injection в шаблоны/SQL-обёртки.

### Кандидаты advisory (проверено через OSV API 2026-09-28)

| # | Advisory | Dep | Класс | Форма продукта | Что доказывает сверх govulncheck |
|---|----------|-----|-------|----------------|----------------------------------|
| C1 | GO-2021-0061 / GHSA-r88r-gmrh-7j83 | `gopkg.in/yaml.v2` | DoS: crafted YAML (nested anchors) | config-loader принимает YAML по сети | provenance: network-input doc vs локальный файл — один dep, два вердикта в разных продуктах |
| C2 | GO-2020-0017 / GHSA-w73w-5m7g-f7qc (CVE-2020-26160) | `github.com/dgrijalva/jwt-go` | auth bypass: `aud` не проверяется | API-сервер с JWT-middleware | условие «валидация вне dep»: `ParseWithClaims`+ручная проверка aud → guard-falsifier vs голый Parse |
| C3 | GO-2024-2698 / GHSA-rhh4-rh7c-7r5v | `github.com/mholt/archiver` (v3) | path traversal в ZIP-extraction | upload-сервис, распаковка архива | sink достижим, но источник — trusted-internal артефакты → verified FALSE / INCONCLUSIVE |
| C4 | GO-2022-0588 | `github.com/microcosm-cc/bluemonday` | XSS: sanitizer bypass | рендер пользовательского HTML | условие «политика фильтрует проблемный узел» — config-gated guard |
| C5 | GO-2023-2102 / GHSA-4374-p667-p6c8 | `golang.org/x/net/http2` | DoS: HTTP/2 rapid reset | h2-сервер с listener | deployment-факты: terminating proxy перед сервером → INCONCLUSIVE вместо чистого govulncheck-hit |
| C6 | GO-2022-0968 / GHSA-gwc9-m7rh-j2ww | `golang.org/x/crypto/ssh` | pre-auth panic: malformed packets | SSH-сервер | exposure-цепочка до pre-auth sink: прямой путь эксплуатации без аутентификации |
| C7 | GO-2024-2800 / GHSA-q64h-39hv-4cf7 | `github.com/hashicorp/go-getter` | argument injection в git-fetch | сервис скачивает по URL пользователя | provenance до sink + URL-whitelist guard → два продукта, EXPLOITABLE vs verified FALSE |
| C8 | GO-2023-2074 / GHSA-m9xq-6h2j-65r2 | `github.com/gomarkdown/markdown` | OOB read в парсере | md-рендерер пользовательского ввода | parser-класс на новом dep; проверка pattern-library обобщаемости |
| C9 | GO-2020-0028 / GHSA-p55x-7x9v-q8m4 | `github.com/miekg/dns` | DoS: malformed zone data | DNS-резолвер сервер | запасной parser-кейс; альтернатива при проблемах с C8 |
| C10 | GO-2023-2409 / GHSA-6294-6rgp-fr7r | `github.com/dvsekhvalnov/jose2go` | DoS: большой p2c в JWE | сервис принимает JWE-токены | numeric bound: гарда `p2c < N` до sink → числовое опровержение условия |
| C11 | любая из C1–C10 на **fixed**-версии dep | — | version-boundary | тот же продукт, dep обновлён | NOT_AFFECTED детерминистично; govulncheck тоже молчит — но мы даём причину и аудит |
| C12 | dep в уязвимой версии, sink не вызывается | `jwt-go`/`archiver` | negative-usage | продукт импортирует dep ради другого API | NV верифицирует falsifier → NO_EXPLOIT_PATH_FOUND vs молчание govulncheck (неотличимо от «нет данных») |

Пара «один advisory → два продукта» (C1, C2, C7) сознательно показывает,
что вердикт зависит от продукта, а не только от advisory — ключевое
отличие от любого сканера манифестов. Итого: 10 новых advisory-кейсов +
2 мета-кейса (version-boundary, negative-usage) → live-слой 11+12=23,
суммарно с fixtures ~41 кейс, 6+ классов, 8+ dep.

Формы продуктов: listener-сервер, CLI arg-driven, config-gated,
deploy-manifest gated, library-consumer, negative-usage (модуль есть,
sink не вызывается — NV-кейс), version-boundary (affected/not-affected
на границе диапазона).

## Фазы

1. **Harness**: `Case.deps`/`module`, генерация `go.mod` в `.gen/`,
   `.gitignore`, тест генерации, `--repo` приоритет сохранён.
2. **Первая партия**: 6–8 real-dep кейсов по ≥4 классам; advisory
   snapshots в `eval/advisories/real/`.
3. **Baseline**: прогон standalone govulncheck per case, поле
   `govulncheck_baseline`, сводная таблица в `eval/README.md`.
4. **Ground truth**: `eval/ground-truth/` для всех позитивных
   вердиктов (включая перенос текущих 5).
5. **Масштабирование**: до ≥30 кейсов суммарно; обновить
   `docs/how-it-works.md` §5 и `eval/README.md`.
6. **Опционально**: курируемый список внешних OSS-продуктов на
   уязвимых тегах в `eval/README.md` (env-переменные, без коммита
   снапшотов).

## Границы и риски

- `go mod download` — сетевая зависимость: кэш GOMODCACHE; в CI —
  отдельный job-маркер; офлайн-прогон fixture corpus не ломается.
- `.gen/` строго в `.gitignore`; проверка: `git status` чист после прогона
  (тест/ручная проверка в done-критерии).
- Никаких committed `go.mod` с уязвимыми requires — проверяется grep'ом
  по дереву как часть done-критерия.
- Keйс-специфичный код в `internal/` запрещён — продукты живут только
  в `eval/products/`.

## Done-критерий

- `eval` прогоняет ≥30 кейсов: ≥4 класса уязвимостей, ≥3 реальных dep.
- Каждый позитивный вердикт имеет `eval/ground-truth/<id>.md`.
- `eval/README.md` содержит baseline-таблицу govulncheck-vs-analyzer.
- `false_safe = 0`, `expect_fail = 0`; `git status` чист после прогона.
- В дереве нет committed уязвимых манифестов (проверено).
