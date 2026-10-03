# Спецификация Analyzer Agent

## 1. Назначение

Analyzer Agent семантически исследует exploitability конкретной уязвимости в конкретном ProductSnapshot. Он не устанавливает окончательный security verdict.

Подробный контракт следующего исследовательского контура:
[LLM-исследование CVE и независимая валидация](llm-cve-analysis-spec.md).
Он задаёт mechanism research до анализа продукта, выбор стратегии,
проверяемые obligations, контекстную критичность и обязательное обоснование
решения. Новое поведение вводится по [отдельному роадмапу](../roadmaps/llm-cve-analysis-roadmap.md);
LLM proposals сохраняют ограничения разделов 8–9 этого документа.

Основной цикл:

```text
REASON -> HYPOTHESIS -> TOOL -> EVIDENCE -> CLAIM -> GAP ANALYSIS
```

## 2. Вход

```go
type AnalysisContext struct {
    CaseID           CaseID
    Vulnerability    Vulnerability
    Product          ProductSnapshot
    RootCause        RootCauseModel
    ExploitModel     ExploitModel
    ExistingEvidence []Evidence
    ExistingClaims   []Claim
    Limits           AnalysisLimits
}
```

Агент не получает весь source tree заранее.

## 3. Выход

```go
type AnalysisResult struct {
    Claims         []Claim
    OpenQuestions  []OpenQuestion
    Uncertainties  []Uncertainty
    AnalysisStatus AnalysisStatus
}
```

Статусы:

- `COMPLETE`;
- `NEEDS_REVIEW`;
- `INSUFFICIENT_EVIDENCE`;
- `LIMIT_REACHED`;
- `TOOL_FAILURE`.

`COMPLETE` означает завершённый сбор evidence, а не «безопасно».

## 4. Exploit Conditions

Условия атомарны и проверяемы. Пример хорошего условия:

> Argument 0 of parser.Parse can contain attacker-controlled HTTP input.

Плохой пример:

> Vulnerability appears exploitable.

Минимальные типы: dependency/package/symbol/reachability, data origin, attacker control, input constraint, validation, configuration, build/platform, authn/authz, runtime, custom.

## 5. Root cause и fix diff

До анализа продукта агент должен понимать механизм уязвимости. При анализе patch необходимо определить:

- что изменилось;
- какое новое ограничение/проверка добавлено;
- какое состояние теперь запрещено;
- какое предположение было неверным в vulnerable version.

Patch нельзя автоматически обобщать за пределы подтверждённого механизма.

## 6. Hypothesis

```go
type Hypothesis struct {
    ID               HypothesisID
    ConditionID      ConditionID
    Statement        string
    ExpectedEvidence []EvidenceKind
    Status           HypothesisStatus
}
```

Каждая гипотеза должна быть проверяема доступным tool.

## 7. Tool calls

Каждый tool call содержит:

- hypothesis_id;
- condition_id;
- purpose;
- typed arguments.

Запрещены широкие чтения source «на всякий случай».

## 8. Evidence semantics

Evidence — только внешне проверяемый факт: go.mod/go.sum/go list/govulncheck/AST/SSA/call graph/source/config/build/tests/runtime/fix diff/advisory.

Текст, сгенерированный LLM, не является Evidence.

## 9. TRUE / FALSE / UNKNOWN

`TRUE` требует положительного факта.

`FALSE` требует более сильной проверки: релевантная область должна быть покрыта достаточно полно.

«Не нашёл» не является `FALSE`.

При недостатке данных использовать `UNKNOWN` и явно перечислять limitations.

## 10. Data flow target

Целевой объект анализа:

```text
source -> transformations -> validation -> sink
```

Origin классифицируется как EXTERNAL_UNTRUSTED, EXTERNAL_AUTHENTICATED, CONFIGURATION, DATABASE, INTERNAL_SERVICE, CONSTANT, GENERATED, UNKNOWN.

## 11. Reachability levels

Различать:

1. module present;
2. package present;
3. vulnerable symbol present;
4. symbol reachable;
5. exploit conditions satisfied.

Ни один предыдущий уровень не заменяет следующий.

## 12. Configuration/build context

Учитывать GOOS, GOARCH, build tags, CGO, generated sources, replace directives, vendor mode и deployment configuration. Default configuration нельзя молча обобщать на все deployment.

## 13. Dynamic behavior

Reflection, unsafe, plugins, dynamic registration, unresolved interface dispatch, function pointers, generated runtime code, embedded scripting, CGO callbacks должны повышать неопределённость. При существенном влиянии condition остаётся UNKNOWN.

## 14. govulncheck

Использовать как evidence для:

- affected dependency/package/symbol;
- call stacks/reachability.

Отрицательный результат не превращать автоматически в `FALSE` exploitability.

## 15. Source search

Поиск source используется для локализации. Ноль совпадений не является доказательством отсутствия, если область поиска неполна или есть динамические механизмы.

## 16. Gap Analysis

После каждой серии действий пересчитать mandatory conditions и выбрать следующий значимый UNKNOWN.

Приоритет:

1. дешёвые проверки, способные дать NOT_AFFECTED;
2. условия, способные подтвердить EXPLOITABLE;
3. условия, способные доказать mitigation/невозможность;
4. supporting context.

## 17. Negative-check pass

Перед использованием `FALSE` попытаться опровергнуть собственный вывод: найти дополнительные callers, interface implementations, runtime registration, alternate entrypoints, build-tagged code, configuration overrides.

## 18. Budget

Агент ограничен количеством итераций, tool calls, source reads, LLM calls и review iterations. При исчерпании — `LIMIT_REACHED` + список unresolved conditions.

## 19. Ошибки инструментов

«Инструмент не смог получить evidence» и «evidence отсутствует» — разные состояния. Ошибка `govulncheck` из-за build failure даёт limitation/UNKNOWN, а не «unreachable».

## 20. Контекст модели

Не передавать transcript. Рабочий контекст собирается из:

- current condition;
- RootCauseModel;
- релевантных evidence summaries;
- current claim;
- known limitations;
- available tools.

## 21. Structured outputs

RootCauseCandidate, ExploitModel, Hypothesis, ClaimProposal, GapAnalysis, Review должны соответствовать JSON Schema. Markdown допускается только для human-readable объяснения.

## 22. Read-only режим

Analyzer может читать repo, строить AST/SSA, запускать анализаторы/build/tests в sandbox. Не может менять продукт, выполнять commit/push, обновлять dependency или создавать PR.

## 23. System prompt — обязательные правила

1. Все security claims считаются UNKNOWN до появления evidence.
2. Нельзя считать уязвимость неэксплуатируемой только из-за отсутствия найденного пути.
3. Каждый TRUE/FALSE ссылается на конкретное evidence.
4. FALSE требует более сильной проверки, чем TRUE.
5. Distinguish dependency/package/symbol/reachability/exploitability.
6. Предпочитать deterministic tools.
7. Делать минимальное число целевых tool calls.
8. Сохранять UNKNOWN при неполноте static analysis.
9. Не изменять repository.
10. Не выдумывать факты о codebase.
11. Каждый tool call связан с hypothesis/condition.
12. Перед безопасным FALSE искать контрпример.
13. При недостатке данных предпочитать INSUFFICIENT_EVIDENCE.

## 24. Completion criterion

Анализ можно завершить, если:

- affected version доказанно false; либо
- все mandatory conditions имеют достаточный TRUE/FALSE; либо
- оставшиеся UNKNOWN невозможно разумно разрешить доступными tools; либо
- исчерпан budget.

## 25. Главный инвариант агента

Analyzer отвечает:

> Какие условия нужны для эксплуатации, какие из них выполняются, какими доказательствами это подтверждается и что осталось неизвестным?

Он не отвечает самостоятельно:

> Можно ли закрыть vulnerability task как безопасную?
