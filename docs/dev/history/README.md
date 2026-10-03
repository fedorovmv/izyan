# История эволюции архитектуры

## Исходный вариант

Первоначальная схема уже строилась вокруг evidence-first анализа:

```text
CVE -> Exploit Model -> govulncheck/call graph -> Evidence -> Claims -> deterministic Verdict
```

Были определены четыре verdict, TRUE/FALSE/UNKNOWN claims, negative evidence semantics, reviewer, persistence и bounded agent loop.

## Что изменилось после разбора похожих проектов

### 1. RootCauseModel выделен отдельно

Ранее vulnerable symbols были частью ExploitModel. После анализа VEX Generation Toolset root cause стал отдельным проверяемым gate:

```text
CVE/fix -> RootCauseModel -> ExploitModel
```

### 2. Добавлен EvidenceGraph как стабильный контракт

Идея взята из OWASP VulnReach: raw outputs инструментов не передаются прямо LLM.

### 3. Убрана идея собственного полного call graph в раннем MVP

Основой Go reachability выбран `govulncheck`; SSA/callgraph остаются targeted tools.

### 4. Full taint engine исключён из MVP

Вместо него: argument provenance, source slicing, validation analysis и право вернуть INCONCLUSIVE.

### 5. EvidenceQuality стала явной

Особенно для heuristic results: route regex/input patterns/source proximity не могут подтверждать safe FALSE.

### 6. Confidence окончательно исключён из verdict logic

Verdict строится только по состояниям mandatory conditions и доказательствам.

## Неизменившиеся базовые принципы

- LLM не является источником фактов;
- path not found != path impossible;
- safe verdict требует evidence;
- `INCONCLUSIVE` предпочтительнее необоснованного `NOT EXPLOITABLE`;
- persisted case является source of truth;
- Reviewer не заменяет deterministic evaluator.

## Структура архива `docs/dev/history/`

- `01-initial-architecture.md`, `go-skeleton-state-machine.md` — начальный bootstrap до реализации ядра.
- `plans/` — архив завершённых планов реализации раннего MVP (12 планов вертикальных срезов).
- `specs/` — архив завершённых дизайн-спецификаций реализованных фич (автономное исследование CVE Срез A, дизайн Inverted Pyramid, локализация RU/EN, function locus, изоляция констант парсеров и доверенная инфраструктура).

