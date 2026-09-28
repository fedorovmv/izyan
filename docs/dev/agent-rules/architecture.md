# Архитектурные изменения

Читать при изменении пайплайна, стадий, доменной модели, границ слоёв.

## Хребет системы

- Сквозной пайплайн — state machine: `CREATED → SNAPSHOT_PRODUCT →
  RESOLVE_VULNERABILITY → CHECK_AFFECTED → RESOLVE_ROOT_CAUSE →
  BUILD_EXPLOIT_MODEL → COLLECT_EVIDENCE → EVALUATE_CONDITIONS →
  [NEGATIVE_CHECK] → [REVIEW] → EVALUATE_VERDICT → BUILD_REPORT →
  COMPLETED`. Новая логика — состояние или evidence-тип, не обходные
  пути.
- Детерминистическое ядро + опциональный LLM-слой: LLM — адаптеры с
  бюджетами и fallback'ами, никогда не источник истины. Всё, что можно
  проверить детерминистически — проверяется детерминистически.
- `AnalysisCase` персистится и рестарт-способен: состояние кейса не
  зависит от LLM-чата. Каждый факт — `Evidence` с provenance в
  `EvidenceGraph` (hash, quality-уровни).
- Вердикт только детерминистический, считается из claims —
  `evaluator.Verdict` читает результат, не вычисляет его из сырья.
- Никаких проприетарных зависимостей: интеграции — generic точки
  (OSV JSON, `--ticket`, VEX-экспорт). Open source.
- Консерватизм: неготовая стадия → INCONCLUSIVE, не «best effort
  вердикт». Неопределённость сохраняется и отображается, не глотается.
