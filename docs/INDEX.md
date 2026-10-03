# Индекс документов

## Структура

- корень `docs/` — документация для пользователей
- `dev/specs/` — спецификации и контракты (что система должна делать;
  нормативные, меняются редко и осознанно)
- `dev/decisions/` — принятые архитектурные решения и запреты
- `dev/roadmaps/` — роадмапы развития фич и исследовательских направлений
  (стратегические документы срезов; после завершения фичи переносятся в архив)
- `dev/current/` — живое состояние для разработчиков: статус,
  gap analysis + бэклог
- `agent-rules/` — рабочие правила для агентов (on-demand, индекс в
  `AGENTS.md`; не проектная документация, а инструкции исполнителя)
- `dev/history/` — исторические версии архитектуры
- [`eval/README.md`](../eval/README.md) — live-корпус (вне `docs/`, рядом с данными корпуса)

## Таблица

### Для пользователей (корень `docs/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`goals-scope.md`](goals-scope.md) | актуальный | Цель, задачи, границы, verdicts, MVP — charter проекта |
| [`architecture.md`](architecture.md) | актуальный | Архитектура: входы/выходы, конвейер состояний, средства, модель данных |
| [`cli.md`](cli.md) | актуальный | Справочник команд, флагов, выходных артефактов |
| [`knowledge-base.md`](knowledge-base.md) | актуальный | База знаний экосистемы: формат файла, расширение `--knowledge`, версии и digest |
| [`how-it-works.md`](how-it-works.md) | актуальный | Методология и гарантии безопасности (Security Deep Dive): вердикты, предохранители, AI governance |

### Для разработчиков (`dev/`)

#### Нормативные спецификации (`dev/specs/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md) | актуальный | Главная спецификация системы |
| [`dev/specs/analyzer-agent-spec.md`](dev/specs/analyzer-agent-spec.md) | актуальный | Контракт поведения Analyzer Agent |
| [`dev/specs/incremental-analysis-value-spec.md`](dev/specs/incremental-analysis-value-spec.md) | reviewed draft | Контракт дополнительной ценности поверх govulncheck; доказательство mandatory input condition |
| [`dev/specs/llm-cve-analysis-spec.md`](dev/specs/llm-cve-analysis-spec.md) | актуальный | Автономное LLM-исследование механизма CVE, стратегии, валидация доказательств, контекстная критичность; B31–B33 |
| [`dev/specs/llm-dismissal-research-spec.md`](dev/specs/llm-dismissal-research-spec.md) | исследовательская | LLM-assisted отклонение, экспертное досье, deployment и контекстная критичность; B27 |

#### Роадмапы развития (`dev/roadmaps/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/roadmaps/llm-cve-analysis-roadmap.md`](dev/roadmaps/llm-cve-analysis-roadmap.md) | в работе | Поэтапная поставка research/dossier, validated proof capabilities и критичности (задачи 1–6 выполнены, 7–16 в плане); B31–B33 |
| [`dev/roadmaps/ingress-closure-roadmap.md`](dev/roadmaps/ingress-closure-roadmap.md) | в работе | Ingress closure: полный inventory входов в reachable dep cone; falsifier `constant-or-generated-input`; B26 |
| [`dev/roadmaps/corpus-expansion-roadmap.md`](dev/roadmaps/corpus-expansion-roadmap.md) | бэклог | Расширение доказательной базы: generated-manifest продукты, baseline vs govulncheck; B13 |
| [`dev/roadmaps/llm-dismissal-research-roadmap.md`](dev/roadmaps/llm-dismissal-research-roadmap.md) | исследование | Пошаговая проверка локального type gate в jose2go: 4 контрольных продукта, baseline, LLM-прогоны и досье; B27 |
| [`dev/roadmaps/llm-advisory-roadmap.md`](dev/roadmaps/llm-advisory-roadmap.md) | бэклог | LLM advisory-контур (D16): параллельная оценка, llm_assessment.json; B17 |

#### Текущее состояние разработки (`dev/current/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/current/gap-analysis.md`](dev/current/gap-analysis.md) | актуальный | Gap analysis спека↔код + канонический бэклог (§2) |
| [`dev/current/implementation-status.md`](dev/current/implementation-status.md) | живой | Хроника реализации срезов и выполненных задач |
| [`dev/current/analysis-internals.md`](dev/current/analysis-internals.md) | актуальный | Механика реализации: evaluators, NV, pattern library, toolchain, audit |

#### Архитектурные решения (`dev/decisions/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md) | актуальный | Ключевые архитектурные решения и запреты (ADR) |
| [`dev/decisions/reference-projects-analysis.md`](dev/decisions/reference-projects-analysis.md) | актуальный | Разбор VEX Toolset / VulnReach / amihit / govulncheck — обоснование решений |

#### История и архив (`dev/history/`)

| Каталог / Файл | Назначение |
|---|---|
| [`dev/history/README.md`](dev/history/README.md) | Описание эволюции архитектуры и структуры архива |
| [`dev/history/01-initial-architecture.md`](dev/history/01-initial-architecture.md) | Исходная архитектура до анализа OSS-референсов |
| [`dev/history/go-skeleton-state-machine.md`](dev/history/go-skeleton-state-machine.md) | Bootstrap-каркас Go-структур до реализации ядра |
| [`dev/history/plans/`](dev/history/plans/) | Архив 12 завершённых планов реализации MVP (`mvp-implementation-plan`, `toolchain-plan`, `exposure-facts-plan`, `pattern-library-plan` и др.) |
| [`dev/history/specs/`](dev/history/specs/) | Архив дизайн-спецификаций реализованных фич (исследование CVE Срез A, Inverted Pyramid отчёта, локализация RU/EN, function locus, изоляция констант парсеров и др.) |

## Рекомендуемый порядок чтения coding-agent'ом

1. [`goals-scope.md`](goals-scope.md)
2. [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md)
3. [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md)
4. [`dev/current/gap-analysis.md`](dev/current/gap-analysis.md) — бэклог открытых задач
5. [`dev/specs/analyzer-agent-spec.md`](dev/specs/analyzer-agent-spec.md) — перед реализацией LLM loop
6. [`architecture.md`](architecture.md) + [`how-it-works.md`](how-it-works.md) — устройство и поведение
7. [`dev/decisions/reference-projects-analysis.md`](dev/decisions/reference-projects-analysis.md) — как reference, не как governing source

При противоречии документов приоритет имеет [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md), затем [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md).
