# Gap-analysis / hypothesis loop — план фичи (gap-analysis #7)

Статус: done (первый слой). Закрывает §18 спеки + таблицу «Hypothesis
loop»: цикл select UNKNOWN → hypothesis → tool → claim → gap analysis.

## До фичи

`Hypothesis`-тип существовал, но нигде не инстанцирулся; пайплайн был
однопроходным: collect → evaluate → verdict. UNKNOWN-claim'ы не имели
аудируемого «что пробовали».

## Архитектура

Новое состояние `GAP_ANALYSIS` между `EVALUATE_CONDITIONS` и
`NEGATIVE_CHECK`:

```text
EVALUATE_CONDITIONS
  hasFalse  → NEGATIVE_CHECK        (без изменений)
  allTrue   → REVIEW                (без изменений)
  unknowns  → GAP_ANALYSIS          (новый переход)
                для каждого UNKNOWN mandatory claim:
                  planner → Hypothesis{Statement, ExpectedEvidence}
                  tool action → новые flows/evidence
                re-evaluate deterministic evaluators
                до фикспоинта (≤3 итераций) или MaxToolCalls
                → диспетч по тем же правилам
```

Скип, когда mandatory уже FALSE — та же экономия, что у LLM-fallback:
FALSE капает вердикт, тратить tool-budget бессмысленно.

## Planner actions (v1)

| Kind | Гипотеза | Действие |
|---|---|---|
| ATTACKER_CONTROL / INPUT_CONSTRAINT (flow UNKNOWN) | «origin резолвится глубже caller-chain» | `TraceArgumentBound` с hops=6; resolved → `ReplaceDataFlow` + CONFIRMED |
| ATTACKER_CONTROL / INPUT_CONSTRAINT (нет call sites) | «синк вызывается через dynamic dispatch» | `ScanDynamic` → маркеры CONFIRMED (документирует потерю покрытия; claim остаётся UNKNOWN) |
| SYMBOL_REACHABLE | «путь через interface dispatch / build-tagged файлы» | `InterfaceDispatchSites` + `GatedRefs` → сайты → CONFIRMED-документация |
| VALIDATION | «guard в caller-frame» | нет инструмента (param-index маппинг через FindCallers) — гипотеза записывается UNRESOLVED как документированный gap |

Инвариант: действия, документирующие потерю покрытия, **никогда не
двигают claim в FALSE** — они объясняют, почему UNKNOWN честен.

## Механика

- `Index.hopLimit` — per-call override `maxTraceHops=2`;
  `TraceArgumentBound(ctx, site, idx, hops)` под мьютексом.
- `EvidenceGraph.ReplaceDataFlow` — углублённый трейс **заменяет**
  UNKNOWN-flow по (ConditionID, sink file:line); append бы не работал —
  evaluator считает `unknown>0 → UNKNOWN`.
- `AnalysisCase.Hypotheses` + `AddHypothesis` (H-ids); секция
  «Hypotheses» в отчёте — аудит INCONCLUSIVE-вердиктов.
- `Usage.ToolCalls` инкрементится на каждое действие — `MaxToolCalls`
  наконец-то имеет потребителя (0 = безлимит для тестов).

## Покрытие

- Фикстура `testdata/deepprod`: цепочка `main→l1→l2→l3→vuln.Parse` —
  3 хопа, глубже дефолтного bound. Без loop'а → UNKNOWN; с loop'ом →
  CONFIRMED-гипотеза, origin EXTERNAL, C-INPUT TRUE, EXPLOITABLE.
- e2e `TestE2EGapAnalysisDeepTrace`; корпус `deep-param-chain`
  (expect EXPLOITABLE + C-PEER-INPUT TRUE).
- Гипотезы пишутся и в INCONCLUSIVE-кейсах (db/svc-flag — UNRESOLVED с
  причиной), давая аудируемую историю.

## Границы

- Planner детерминистичен и покрывает три kind; VALIDATION в caller
  frame — зафиксированный gap.
- Reviewer-driven repair loop (REVIEW → REPAIR_ANALYSIS) — отдельная
  ветка, не этот слой: state `REPAIR_ANALYSIS` объявлен, не используется.
- Глубокий трейс всё ещё bounded (6); цепочки глубже остаются UNKNOWN.
- LLM-agent hypothesis selection (спека §16 — агент сам выбирает
  инструменты) не реализована — это слой над typed tools #6.
