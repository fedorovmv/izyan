# Индекс документов

## Структура

- корень `docs/` — документация для пользователей
- `dev/specs/` — спецификации и контракты (что система должна делать;
  нормативные, меняются редко и осознанно)
- `dev/decisions/` — принятые архитектурные решения и запреты
- `dev/plans/` — планы реализации фич (рабочие документы срезов; после
  завершения остаются как история решения, статус в колонке)
- `dev/current/` — живое состояние для разработчиков: статус,
  gap analysis + бэклог
- `agent-rules/` — рабочие правила для агентов (on-demand, индекс в
  `AGENTS.md`; не проектная документация, а инструкции исполнителя)
- `dev/history/` — исторические версии архитектуры
- `eval/README.md` — live-корпус (вне `docs/`, рядом с данными корпуса)

## Таблица

### Для пользователей (корень `docs/`)

| Файл | Статус | Назначение |
|---|---|---|
| `goals-scope.md` | актуальный | Цель, задачи, границы, verdicts, MVP — charter проекта |
| `architecture.md` | актуальный | Архитектура: входы/выходы, конвейер состояний, средства, модель данных |
| `cli.md` | актуальный | Справочник команд, флагов, выходных артефактов |
| `how-it-works.md` | актуальный | Гарантии (вердикты), артефакты, известные границы |

### Для разработчиков (`dev/`)

| Файл | Статус | Назначение |
|---|---|---|
| `dev/specs/governing-spec.md` | актуальный | Главная спецификация системы |
| `dev/specs/analyzer-agent-spec.md` | актуальный | Контракт поведения Analyzer Agent |
| `dev/decisions/architecture-decisions.md` | актуальный | Ключевые архитектурные решения и запреты |
| `dev/decisions/reference-projects-analysis.md` | актуальный | Разбор VEX Toolset/VulnReach/amihit/govulncheck — обоснование решений |
| `dev/current/analysis-internals.md` | актуальный | Механика реализации: evaluators, NV, pattern library, toolchain, audit |
| `dev/current/implementation-status.md` | живой | Статус срезов MVP, что сделано/что дальше |
| `dev/current/gap-analysis.md` | актуальный | Gap analysis спека↔код + канонический бэклог (§5) |
| `dev/plans/mvp-implementation-plan.md` | актуальный | Порядок реализации и milestones |
| `dev/plans/pattern-library-plan.md` | done | Exploit Pattern Library: classify → patterns → conditions |
| `dev/plans/exposure-facts-plan.md` | done | Deployment/exposure facts: listeners, dial-sites, `C-EXPOSURE` |
| `dev/plans/negative-coverage-plan.md` | done | NV scope: build-tag-excluded files + interface dispatch |
| `dev/plans/config-reading-plan.md` | done | Configuration reading: `config_flag`/`config_key`, `C-TLS-VERIFY` |
| `dev/plans/eval-harness-plan.md` | done | Eval harness: корпус, метрики, false-safe; `analyzer eval` |
| `dev/plans/toolchain-plan.md` | done | Target Go toolchain: SDK/GOTOOLCHAIN/docker, toolchain provenance |
| `dev/plans/data-origins-plan.md` | done | Provenance: DATABASE/INTERNAL_SERVICE origins, populate/passthrough |
| `dev/plans/tool-audit-plan.md` | done | `tool_executions` audit: ctx-рекордер, ToolVersion, отчёт |
| `dev/plans/gap-loop-plan.md` | done | Gap-analysis: GAP_ANALYSIS state, гипотезы, bounded loop |
| `dev/plans/typed-tools-plan.md` | done | Все 17 typed tools §17; exec-gate `--allow-exec` |
| `dev/plans/knowledge-base-plan.md` | plan | Knowledge-base таблицы → данные (`--knowledge` JSON); бэклог B12 |
| `dev/history/go-skeleton-state-machine.md` | исторический | Bootstrap-каркас: Go-интерфейсы/структуры до реализации (истина теперь — `internal/`) |
| `dev/history/01-initial-architecture.md` | исторический | Исходная архитектура до разбора OSS |
| `dev/history/README.md` | исторический | Что изменилось и почему |

## Рекомендуемый порядок чтения coding-agent'ом

1. `docs/goals-scope.md`
2. `docs/dev/specs/governing-spec.md`
3. `docs/dev/decisions/architecture-decisions.md`
4. `docs/dev/plans/mvp-implementation-plan.md`
5. `docs/dev/specs/analyzer-agent-spec.md` — перед реализацией LLM loop
6. `docs/architecture.md` + `docs/how-it-works.md` — устройство и поведение
7. `docs/dev/decisions/reference-projects-analysis.md` — как reference, не как governing source

При противоречии документов приоритет имеет `docs/dev/specs/governing-spec.md`, затем `docs/dev/decisions/architecture-decisions.md`.
