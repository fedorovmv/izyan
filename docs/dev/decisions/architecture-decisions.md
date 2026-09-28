# Ключевые архитектурные решения

## D1. Verdict только детерминированный

LLM не имеет API для установки `NOT_AFFECTED`, `EXPLOITABLE`, `NO_EXPLOIT_PATH_FOUND`, `INCONCLUSIVE`.

## D2. Root cause — отдельный gate

Нельзя строить глубокий exploitability analysis относительно случайно выбранной функции. Ambiguous/not found -> INCONCLUSIVE.

## D3. ExploitModel состоит из обязательных условий

Reachability не равно exploitability. Каждая CVE разлагается на минимальные mandatory conditions.

## D4. EvidenceGraph — стабильная граница

LLM/reviewer не зависят от raw JSON конкретных scanner versions.

## D5. NO EVIDENCE != FALSE

Отрицательное заключение требует положительного доказательства невозможности условия.

## D6. FALSE сильнее TRUE

Safe FALSE проходит отдельный negative-check и попытку найти контрпример.

## D7. govulncheck раньше собственного call graph

Не писать в MVP то, что уже решает Go toolchain. Собственные SSA/AST tools нужны только для targeted gaps.

## D8. Не писать full taint engine в MVP

Сначала targeted argument provenance + validation + source slicing. Сложные случаи могут законно завершаться INCONCLUSIVE.

## D9. Confidence не участвует в security verdict

Confidence используется только для review priority/UI.

## D10. CVSS/EPSS/KEV/PoC отделены от exploitability

Они влияют на risk priority/SLA, но не доказывают applicability/exploitability продукта.

## D11. Один основной Analyzer + Reviewer

Не строить committee/majority multi-agent систему. Reviewer проверяет claims/evidence, а не голосует за итог.

## D12. Persisted state важнее LLM transcript

Анализ должен быть restartable, auditable и model-independent.

## D13. LLM context должен быть bounded

Передавать только current condition + relevant evidence/source fragments + limitations + available tools.

## D14. Режим deterministic-only обязателен

Он нужен для диагностики границы между фактическим анализом и LLM reasoning.

## D15. Remediation отделён

Сначала измеряется качество exploitability analysis. Автообновление зависимостей/кода добавляется позже.
