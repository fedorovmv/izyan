# CLI-справочник

Бинарь собирается как `izyan` (`go build -o izyan ./cmd/izyan`). Пять сабкоманд: `analyze`, `scan`, `eval`, `remediate`, `knowledge`.

## analyze — полный анализ одной advisory

```bash
izyan analyze --repo /src/product --vuln GO-2025-3595 [флаги]
```

Прогоняет весь конвейер ([`architecture.md`](architecture.md)) по одной уязвимости и
создаёт кейс в `--case-dir`.

Вход advisory — ровно один из:

| Флаг | Что делает |
|---|---|
| `--vuln <id>` | ID `GO-…`/`CVE-…`/`GHSA-…`; документ грузится из OSV API |
| `--vuln-file <path>` | локальный OSV JSON вместо API |
| `--ticket <path>` | тикет из трекера задач: generic JSON, выгрузка из Jira/GitLab/трекера, произвольный скопированный текст или `-` для stdin. Автоматически извлекает ID уязвимости, номер тикета, компонент, релиз, пакет и advisory |
| `--ticket-id <id>` | ключ тикета для выбора из списка/массива в ticket JSON |
| `--repo-map <path>` | путь к JSON-файлу маппинга компонентов/тикетов на локальные пути репозиториев (по умолчанию ищется `repos.json` в текущей директории) |

Флаги продукта:

| Флаг | Что делает |
|---|---|
| `--repo <path>` | путь к Go-репозиторию продукта (обязателен, если не разрешён через `--ticket` и `--repo-map` / `repos.json`) |
| `--goos`, `--goarch` | целевая платформа снапшота |
| `--build-tags <t1,t2>` | build tags при загрузке пакетов |
| `--binary <path>` | собранный бинарь релиза: `govulncheck -mode binary` + реальный toolchain и модули из встроенного build info |
| `--release-go-version <ver>` | версия Go, которой собран релиз (из тикета/релиз-нот) — для `std`-advisory |

Ручные входы (обходят автоматику, полезны при отсутствии fix-commit):

| Флаг | Что делает |
|---|---|
| `--root-cause <pkg/path.Symbol>` | уязвимый символ вручную; повторяемый флаг |
| `--exploit-model <path>` | готовая модель условий эксплуатации JSON |
| `--non-locus-basis <sym:reason[:author]>` | экспертное исключение символа из сайтов дефекта (L = declared set − basis); повторяемый флаг |
| `--accept-locus-proposals` | автоматически применить проверенные машинные предложения (`ProposedNonLocus`) в модель анализа без ручного ввода `--non-locus-basis` (не модифицирует код продукта) |

### Интеграция с трекерами задач и произвольным текстом (`--ticket`)

Анализатор поддерживает автоматический умный импорт информации без необходимости вручную вычленять идентификаторы:

1. **Произвольный текст или буфер обмена (`--ticket -` или `--ticket file.txt`):**
   ```bash
   # Передача скопированного описания тикета через stdin:
   pbpaste | izyan analyze --ticket - --repo /path/to/project
   ```
   Анализатор автоматически находит:
   - Идентификаторы уязвимостей (`GO-…`, `CVE-…`, `GHSA-…`, `BDU:…`);
   - Номер тикета (`[A-Z]+-\d+`, например `SEC-538506`, `JIRA-1234`, `APP-1001`);
   - Затронутую библиотеку/модуль и версию;
   - Название компонента и релиза.
   Номер тикета, компонент и релиз автоматически сохраняются в кейсе и выводятся в `report.md`, `report.en.md` и `report.json`.

2. **JSON-выгрузки трекеров (Jira, GitLab, Bugzilla и др.):**
   ```bash
   izyan analyze --ticket ticket.json --repo /path/to/project
   ```
   Если JSON-файл содержит массив тикетов, можно выбрать нужный по ключу:
   ```bash
   izyan analyze --ticket tickets.json --ticket-id APP-1002
   ```

3. **Автоматический поиск репозитория по компоненту (`--repo-map` или `repos.json`):**
   Чтобы не передавать `--repo` каждый раз вручную, можно завести `repos.json` (или `.izyan-repos.json`) в текущей директории либо передать `--repo-map <path>`:
   ```json
   {
     "GATEWAY": "/Users/developer/work/gateway",
     "CORE": "/Users/developer/work/core",
     "SEC-1001": "/Users/developer/work/gateway"
   }
   ```
   Или в структурированном виде:
   ```json
   {
     "components": { "GATEWAY": "/Users/developer/work/gateway" },
     "tickets":    { "SEC-1001": "/Users/developer/work/gateway" }
   }
   ```
   При запуске `izyan analyze --ticket ticket.json` анализатор автоматически сопоставит компонент или номер тикета с локальным репозиторием.

## scan — массовый прогон зависимостей

```bash
izyan scan --repo /src/product [--max-vulns 50]
```

Опрашивает OSV по всем зависимостям (`go list -m all`), дёшево
отсекает детерминистически-неаффектящие advisory и прогоняет выжившие
через полный пайплайн `analyze`. Сводка — `<case-dir>/scan.json`.

| Флаг | Что делает |
|---|---|
| `--max-vulns <n>` | потолок advisory для глубокого анализа (default 50) |

## remediate — исправление уязвимой зависимости

```bash
izyan remediate --repo /src/product --vuln GO-2025-3595 [--apply] [--run-tests] [--worktree /tmp/wt]
```

Без `--apply` — только план (минимальный `go get` до fixed-версии +
ожидаемый re-analyze). С `--apply` — реально мутирует `go.mod/go.sum`.

| Флаг | Что делает |
|---|---|
| `--apply` | применить фикс (`go get` + `go mod tidy`) |
| `--run-tests` | после фикса прогнать `go test ./...` до re-analyze |
| `--worktree <path>` | apply в `git worktree` — исходный checkout не трогается |

## eval — регрессионный корпус (для разработчиков)

```bash
izyan eval --corpus eval/corpus.json [--case <id|glob>] [-j <n>] [--clean] [--out report.md] [--json report.json] [--with-llm]
```

Прогоняет корпус кейсов через пайплайн, считает метрики
(`false_safe` — стоп-критерий, должен быть 0). Exit code 1 при любом
false-safe/expect-fail/claims-fail/error — пригоден для CI.
По умолчанию детерминистичен; `--with-llm` — opt-in замер LLM-варианта.
Флаг `--case <id|glob>` фильтрует кейсы (например `--case real-yaml*` или `--case real-yaml-const`), `-j <n>` задаёт размер параллельного пула воркеров (по умолчанию 4), `--clean` форсирует перегенерацию модулей в `.gen/`.
Пути в корпусе — относительно файла корпуса, `${VAR}` раскрывается
([`eval/README.md`](../eval/README.md)).

## knowledge — база знаний экосистемы

База знаний — таблицы семантики API экосистемы, по которым анализ
резолвит provenance и exposure (что такое база и почему она версиони-
руется — [`knowledge-base.md`](knowledge-base.md)). Встроенная база
embedded в бинарь и знает только публичные API: вызовы внутренних
библиотек продукта останутся `UNKNOWN`-provenance — их дописывают
расширением `--knowledge <file>` **без пересборки**.

```bash
izyan knowledge [--knowledge <path>]
```

Печатает эффективную базу в JSON — дефолты либо дефолты + расширение.
Дамп — шаблон для своего файла и валидатор: ошибки схемы/мержа
показываются до прогона анализа. Формат файла, поля и правила мержа —
в [`knowledge-base.md`](knowledge-base.md).

## Общие флаги (все сабкоманды)

| Флаг | Что делает |
|---|---|
| `--case-dir <path>` | каталог состояния кейсов (default `.izyan`) |
| `--lang <ru\|en>` | язык формирования отчётов и вывода CLI (default `ru`) |
| `--osv-url <url>` | альтернативный OSV API endpoint |
| `--cve-analysis <mode>` | режим автономного LLM CVE-исследования (`off`, `assist`, `verified`, default `off`) |
| `--strict-llm` | режим fail-fast: падать с ошибкой при сбое LLM, не переключаясь на детерминистику |
| `--deterministic-only` | выключить весь LLM-слой |
| `--mem-limit <size>` | лимит оперативной памяти процесса с watchdog (default `4GiB`) |
| `--allow-exec` | разрешить запуск кода репозитория (run_build/run_tests в доказательствах). Без флага exec-инструменты недоступны |
| `--knowledge <path>` | JSON-расширение базы знаний экосистемы — дописывает записи для API, которых нет во встроенной базе (внутренние библиотеки продукта). Формат, валидация и семантика мержа: [`knowledge-base.md`](knowledge-base.md). Дамп базы/шаблон: `izyan knowledge` |
| `--llm-env <path>` | файл с LLM-кредами; иначе `.env` в cwd или корне репо |

## LLM-конфигурация

LLM-слой включается только при `LLM_ENABLED` в truthy-значении
(`1`/`true`/`yes`/`on`) — иначе анализ идёт детерминистически.
Переменные читаются из окружения или из dotenv-файла: явный `--llm-env
<path>`, иначе `.env` в cwd или в корне `--repo`. Значения из
dotenv **не переопределяют** уже выставленные переменные окружения.

Выбор backend'а: промпты анализатора — про уязвимости и эксплойт-
модели, поэтому провайдеры с safety-фильтрами (Gemini и подобные)
могут отвечать отказом — в отчёте это видно как `provider refusal
(content filter)` в limitation/findings. Рекомендуются self-hosted
модели за OpenAI-compatible gateway (корпоративный aihub, ollama и
т.п.); отказ не ломает анализ — слой откатывается в детерминистику.

| Переменная | Что задаёт |
|---|---|
| `LLM_ENABLED` | `1`/`true`/`yes`/`on` — включает слой; иначе выключен |
| `LLM_BASE_URL` | endpoint LLM API (OpenAI-compatible) |
| `LLM_API_KEY` | ключ доступа |
| `LLM_ANALYZE_MODEL` | модель для root cause/review/gap-planner |
| `LLM_BUILD_MODEL` | модель для построения exploit-модели (default: `LLM_ANALYZE_MODEL`) |
| `LLM_MAX_TOKENS` | потолок токенов ответа (default 4000) |
| `LLM_TIMEOUT_SEC` | таймаут запроса (default 120) |
| `LLM_INSECURE_TLS` | `1`/`true` — отключить проверку TLS к endpoint'у |
| `LLM_BUILD_MAX_RETRIES` | retries JSON-repair для build-модели (default 0) |

Пример `.env`:

```dotenv
LLM_ENABLED=1
LLM_BASE_URL=https://llm.example.com/v1
LLM_API_KEY=sk-...
LLM_ANALYZE_MODEL=gpt-4o
LLM_BUILD_MODEL=gpt-4o
```

`.env*` файлы в `.gitignore` — не коммитятся.

## Прочие переменные окружения

| Переменная | Где используется |
|---|---|
| `${VAR}` внутри corpus JSON | `eval` раскрывает env в `repo`-путях (`VA_PRODUCT_REPO` для живого корпуса, см. [`eval/README.md`](../eval/README.md)) |
| `GOMODCACHE`, `GOPATH` | source-инструменты `read_source`/`search_source` допускают module cache как evidence-область |

## Что создаётся на выходе

`<case-dir>/<case-id>/`:

- `report.json`, `report.md` — вердикт, claims с evidence, limitations;
- `tracker_comment.md` — готовый комментарий для трекера;
- `openvex.json`, `cyclonedx.json` — экспорты вердикта;
- сериализованный `AnalysisCase` — restartable состояние + аудит
  (`tool_executions`: tool, args, exit code, sha256 stdout/stderr).

## Ограничения и бюджеты

Встроенные потолки на прогон: ≤64 итераций workflow, ≤128 tool calls,
≤32 LLM calls, ≤256 чтений исходников, ≤2 repair-итераций. Исчерпание —
честный `INCONCLUSIVE`/`UNKNOWN` с limitation, а не тихий обрыв.

Exit codes: `0` — кейс завершён с вердиктом (включая INCONCLUSIVE);
не-ноль — инфраструктурный сбой пайплайна (`FAILED`); у `eval` — как
описано выше.
