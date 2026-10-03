# LLM advisory-контур — спека для проработки (бэклог B17, решение D16)

Статус: spec-draft. Отвечает на вопрос: как LLM оценивает то, что
детерминистический контур не смог, — параллельно, репортируемо,
никогда не авторитетно.

## Проблема

Детерминистический контур честно останавливается на UNKNOWN: opaque
callee, семантика метода не выводима из кода, deployment-условия.
Пользователь при этом не видит, «что думает ИИ» — ценность LLM-слоя
для триажа теряется, а расхождения «модель vs движок» не становятся
сигналом для ревью.

## Дизайн

### Контур

Параллельная read-only оценка поверх **завершённого** кейса — после
EVALUATE_VERDICT / REVIEW, до финализации отчёта. Advisory видит все
собранные evidence и claims, но пишет только в свой артефакт.

```
case (post-review) → llm.Advisor → llm_assessment.json
                                   + `## LLM assessment` в report.md
```

Не меняет: EvidenceGraph authoritative-часть, claims, verdict,
NV-статусы. `--deterministic-only` гасит контур целиком; отказ LLM →
секция отсутствует + limitation, анализ не ломается.

### Содержимое `llm_assessment.json`

- `subjects[]`: per unresolvable callee / UNKNOWN-claim —
  `{symbol, proposed_semantics: source|passthrough|guard|sink|neutral,
    confidence, rationale, suggested_knowledge_entry?}`
- `verdict_estimate`: `{estimate, rationale, key_uncertainties[]}` —
  что модель думает о вердикте целиком.
- `divergence`: assessment vs deterministic verdict — совпадение
  фиксируется как agreement-сигнал; расхождение → finding `ADV-1..n`
  со severity и ссылкой на условие (чекпоинт человека, не override).

### Граница (инварианты)

- Advisory не создаёт и не меняет claim'ы, не пишет falsifier'ы,
  не участвует в вердикте. Все его находки — finding/предложение.
- `suggested_knowledge_entry` — только draft; применение — через
  `--knowledge` после человеческого ревью (правила мержа B12 не
  ослабляются).
- Метка источника в отчёте: каждая advisory-строка помечена
  «llm-assessed, не верифицировано движком» — чтобы читающий не путал
  оценку с фактом.

### Промпт-границы

Per-subject контракт: сигнатура + тело callee (read_function) + claim
контекст + список уже собранных origins. Бюджеты — общие
MaxLLMCalls/таймаут; on-budget-exhausted → частичный assessment
допустим, limitation фиксируется.

## Почему это не ломает «детерминистический авторитет»

Разделение труда: advisory делает рассуждение, движок — доказательство.
Совпадение контуров повышает доверие к выводу; расхождение — явный
сигнал ревью. Продуктовая формула: «ИИ анализирует, движок доказывает,
расхождение видно». Конкурирует с LLM-only подходами именно
аудируемостью границы.

## Метрики

- agreement-rate advisory-estimate vs verdict на корпусе (в eval-report)
- доля subjects, где suggested semantics впоследствии подтверждена
  детерминистическим трейсом (вклад в B16)

## Фазы

1. Schema `llm_assessment.json` + `llm.Advisor` (subjects + estimate)
   + секция в report.md; кейс без UNKNOWN — пустой assessment.
2. Divergence-findings `ADV-*`, подсветка в report.md.
3. Eval: agreement метрика; связка с B16 (confirmed semantics →
   hypothesis input для GAP_ANALYSIS).

## Done-критерий

- `llm_assessment.json` рядом с report.* на любом кейсе с UNKNOWN/
  unresolvable subjects; отключение `--deterministic-only` чистит его.
- Divergence производит finding, agreement — явную пометку.
- Unit: advisory не мутирует claims/EvidenceGraph/verdict (assert на
  snapshot кейса до/после Advisor).
- Корпус: прогон фикстур с advisory — verdict distribution не меняется,
  false_safe=0 сохраняется.
