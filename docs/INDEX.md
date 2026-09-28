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
- [`eval/README.md`](../eval/README.md) — live-корпус (вне `docs/`, рядом с данными корпуса)

## Таблица

### Для пользователей (корень `docs/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`goals-scope.md`](goals-scope.md) | актуальный | Цель, задачи, границы, verdicts, MVP — charter проекта |
| [`architecture.md`](architecture.md) | актуальный | Архитектура: входы/выходы, конвейер состояний, средства, модель данных |
| [`cli.md`](cli.md) | актуальный | Справочник команд, флагов, выходных артефактов |
| [`knowledge-base.md`](knowledge-base.md) | актуальный | База знаний экосистемы: формат файла, расширение `--knowledge`, версии и digest |
| [`how-it-works.md`](how-it-works.md) | актуальный | Гарантии (вердикты), артефакты, известные границы |

### Для разработчиков (`dev/`)

| Файл | Статус | Назначение |
|---|---|---|
| [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md) | актуальный | Главная спецификация системы |
| [`dev/specs/analyzer-agent-spec.md`](dev/specs/analyzer-agent-spec.md) | актуальный | Контракт поведения Analyzer Agent |
| [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md) | актуальный | Ключевые архитектурные решения и запреты |
| [`dev/decisions/reference-projects-analysis.md`](dev/decisions/reference-projects-analysis.md) | актуальный | Разбор VEX Toolset/VulnReach/amihit/govulncheck — обоснование решений |
| [`dev/current/analysis-internals.md`](dev/current/analysis-internals.md) | актуальный | Механика реализации: evaluators, NV, pattern library, toolchain, audit |
| [`dev/current/implementation-status.md`](dev/current/implementation-status.md) | живой | Статус срезов MVP, что сделано/что дальше |
| [`dev/current/gap-analysis.md`](dev/current/gap-analysis.md) | актуальный | Gap analysis спека↔код + канонический бэклог (§2) |
| [`dev/plans/mvp-implementation-plan.md`](dev/plans/mvp-implementation-plan.md) | актуальный | Порядок реализации и milestones |
| [`dev/plans/pattern-library-plan.md`](dev/plans/pattern-library-plan.md) | done | Exploit Pattern Library: classify → patterns → conditions |
| [`dev/plans/exposure-facts-plan.md`](dev/plans/exposure-facts-plan.md) | done | Deployment/exposure facts: listeners, dial-sites, `C-EXPOSURE` |
| [`dev/plans/negative-coverage-plan.md`](dev/plans/negative-coverage-plan.md) | done | NV scope: build-tag-excluded files + interface dispatch |
| [`dev/plans/config-reading-plan.md`](dev/plans/config-reading-plan.md) | done | Configuration reading: `config_flag`/`config_key`, `C-TLS-VERIFY` |
| [`dev/plans/eval-harness-plan.md`](dev/plans/eval-harness-plan.md) | done | Eval harness: корпус, метрики, false-safe; `analyzer eval` |
| [`dev/plans/toolchain-plan.md`](dev/plans/toolchain-plan.md) | done | Target Go toolchain: SDK/GOTOOLCHAIN/docker, toolchain provenance |
| [`dev/plans/data-origins-plan.md`](dev/plans/data-origins-plan.md) | done | Provenance: DATABASE/INTERNAL_SERVICE origins, populate/passthrough |
| [`dev/plans/tool-audit-plan.md`](dev/plans/tool-audit-plan.md) | done | `tool_executions` audit: ctx-рекордер, ToolVersion, отчёт |
| [`dev/plans/gap-loop-plan.md`](dev/plans/gap-loop-plan.md) | done | Gap-analysis: GAP_ANALYSIS state, гипотезы, bounded loop |
| [`dev/plans/typed-tools-plan.md`](dev/plans/typed-tools-plan.md) | done | Все 17 typed tools §17; exec-gate `--allow-exec` |
| [`dev/plans/knowledge-base-plan.md`](dev/plans/knowledge-base-plan.md) | done | Knowledge-base таблицы → данные (`--knowledge` JSON); бэклог B12 |
| [`dev/plans/corpus-expansion-plan.md`](dev/plans/corpus-expansion-plan.md) | plan | Расширение доказательной базы: generated-manifest продукты, baseline vs govulncheck; бэклог B13 |
| [`dev/plans/llm-advisory-plan.md`](dev/plans/llm-advisory-plan.md) | spec-draft | LLM advisory-контур (D16): параллельная оценка, llm_assessment.json; бэклог B17 |
| [`dev/history/go-skeleton-state-machine.md`](dev/history/go-skeleton-state-machine.md) | исторический | Bootstrap-каркас: Go-интерфейсы/структуры до реализации (истина теперь — `internal/`) |
| [`dev/history/01-initial-architecture.md`](dev/history/01-initial-architecture.md) | исторический | Исходная архитектура до разбора OSS |
| [`dev/history/README.md`](dev/history/README.md) | исторический | Что изменилось и почему |

## Рекомендуемый порядок чтения coding-agent'ом

1. [`goals-scope.md`](goals-scope.md)
2. [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md)
3. [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md)
4. [`dev/plans/mvp-implementation-plan.md`](dev/plans/mvp-implementation-plan.md)
5. [`dev/specs/analyzer-agent-spec.md`](dev/specs/analyzer-agent-spec.md) — перед реализацией LLM loop
6. [`architecture.md`](architecture.md) + [`how-it-works.md`](how-it-works.md) — устройство и поведение
7. [`dev/decisions/reference-projects-analysis.md`](dev/decisions/reference-projects-analysis.md) — как reference, не как governing source

При противоречии документов приоритет имеет [`dev/specs/governing-spec.md`](dev/specs/governing-spec.md), затем [`dev/decisions/architecture-decisions.md`](dev/decisions/architecture-decisions.md).
