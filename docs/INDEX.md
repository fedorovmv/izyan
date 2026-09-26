# Индекс документов

| Файл | Статус | Назначение |
|---|---|---|
| `current/00-goals-scope.md` | актуальный | Цель, задачи, границы, verdicts, MVP |
| `current/01-governing-spec.md` | актуальный | Главная спецификация системы |
| `current/02-analyzer-agent-spec.md` | актуальный | Контракт поведения Analyzer Agent |
| `current/03-mvp-implementation-plan.md` | актуальный | Порядок реализации и milestones |
| `current/04-go-skeleton-state-machine.md` | актуальный | Go domain/contracts/workflow |
| `current/05-reference-projects-analysis.md` | актуальный | Анализ VEX Toolset/VulnReach/amihit/govulncheck |
| `current/06-decisions.md` | актуальный | Ключевые архитектурные решения и запреты |
| `current/07-implementation-status.md` | живой | Статус срезов MVP, что сделано/что дальше |
| `current/08-how-it-works.md` | актуальный | Алгоритм работы: пайплайн, evaluators, negative check, особенности govulncheck |
| `current/09-gap-analysis.md` | актуальный | Gap analysis спека↔код: что не сделано и почему |
| `current/10-pattern-library-plan.md` | план | Exploit Pattern Library: classify → patterns → conditions |
| `current/11-exposure-facts-plan.md` | done | Deployment/exposure facts: listeners, dial-sites, `C-EXPOSURE` |
| `history/01-initial-architecture.md` | исторический | Исходная архитектура до разбора OSS |
| `history/README.md` | исторический | Что изменилось и почему |

## Рекомендуемый порядок чтения coding-agent'ом

1. `00-goals-scope.md`
2. `01-governing-spec.md`
3. `06-decisions.md`
4. `03-mvp-implementation-plan.md`
5. `04-go-skeleton-state-machine.md`
6. `02-analyzer-agent-spec.md` — перед реализацией LLM loop
7. `08-how-it-works.md` — как код реально работает сейчас
8. `05-reference-projects-analysis.md` — как reference, не как governing source

При противоречии документов приоритет имеет `01-governing-spec.md`, затем `06-decisions.md`.
