# CLI-справочник

Бинарь собирается как `vuln-analyzer` (`go build -o vuln-analyzer
./cmd/analyzer`). Пять сабкоманд: `analyze`, `scan`, `eval`,
`remediate`, `knowledge`.

## analyze — полный анализ одной advisory

```bash
vuln-analyzer analyze --repo /src/product --vuln GO-2025-3595 [флаги]
```

Прогоняет весь конвейер ([`architecture.md`](architecture.md)) по одной уязвимости и
создаёт кейс в `--case-dir`.

Вход advisory — ровно один из:

| Флаг | Что делает |
|---|---|
| `--vuln <id>` | ID `GO-…`/`CVE-…`/`GHSA-…`; документ грузится из OSV API |
| `--vuln-file <path>` | локальный OSV JSON вместо API |
| `--ticket <path>` | generic tracker-тикет JSON: id уязвимости, repo, embedded/synthesized advisory — точка интеграции с внешним трекером |

Флаги продукта:

| Флаг | Что делает |
|---|---|
| `--repo <path>` | путь к Go-репозиторию продукта (обязателен) |
| `--goos`, `--goarch` | целевая платформа снапшота |
| `--build-tags <t1,t2>` | build tags при загрузке пакетов |
| `--binary <path>` | собранный бинарь релиза: `govulncheck -mode binary` + реальный toolchain и модули из встроенного build info |
| `--release-go-version <ver>` | версия Go, которой собран релиз (из тикета/релиз-нот) — для `std`-advisory |

Ручные входы (обходят автоматику, полезны при отсутствии fix-commit):

| Флаг | Что делает |
|---|---|
| `--root-cause <pkg/path.Symbol>` | уязвимый символ вручную; повторяемый флаг |
| `--exploit-model <path>` | готовая модель условий эксплуатации JSON |

## scan — массовый прогон зависимостей

```bash
vuln-analyzer scan --repo /src/product [--max-vulns 50]
```

Опрашивает OSV по всем зависимостям (`go list -m all`), дёшево
отсекает детерминистически-неаффектящие advisory и прогоняет выжившие
через полный пайплайн `analyze`. Сводка — `<case-dir>/scan.json`.

| Флаг | Что делает |
|---|---|
| `--max-vulns <n>` | потолок advisory для глубокого анализа (default 50) |

## remediate — исправление уязвимой зависимости

```bash
vuln-analyzer remediate --repo /src/product --vuln GO-2025-3595 [--apply] [--run-tests] [--worktree /tmp/wt]
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
vuln-analyzer eval --corpus eval/corpus.json [--out report.md] [--json report.json] [--with-llm]
```

Прогоняет корпус кейсов через пайплайн, считает метрики
(`false_safe` — стоп-критерий, должен быть 0). Exit code 1 при любом
false-safe/expect-fail/claims-fail/error — пригоден для CI.
По умолчанию детерминистичен; `--with-llm` — opt-in замер LLM-варианта.
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
vuln-analyzer knowledge [--knowledge <path>]
```

Печатает эффективную базу в JSON — дефолты либо дефолты + расширение.
Дамп — шаблон для своего файла и валидатор: ошибки схемы/мержа
показываются до прогона анализа. Формат файла, поля и правила мержа —
в [`knowledge-base.md`](knowledge-base.md).

## Общие флаги (все сабкоманды)

| Флаг | Что делает |
|---|---|
| `--case-dir <path>` | каталог состояния кейсов (default `.vuln-analyzer`) |
| `--osv-url <url>` | альтернативный OSV API endpoint |
| `--deterministic-only` | выключить весь LLM-слой |
| `--allow-exec` | разрешить запуск кода репозитория (run_build/run_tests в доказательствах). Без флага exec-инструменты недоступны |
| `--knowledge <path>` | JSON-расширение базы знаний экосистемы — дописывает записи для API, которых нет во встроенной базе (внутренние библиотеки продукта). Формат, валидация и семантика мержа: [`knowledge-base.md`](knowledge-base.md). Дамп базы/шаблон: `vuln-analyzer knowledge` |
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
