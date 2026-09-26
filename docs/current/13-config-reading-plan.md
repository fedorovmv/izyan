# Configuration reading: config_flag/config_key checks — план фичи (gap-analysis кандидат #3)

Статус: done. Закрывает пункт #3 приоритета и строку
«CONFIGURATION-условия» `09-gap-analysis.md`.

## Проблема

`CONFIGURATION` condition kind существует, но evaluator'а нет: любое
конфигурационное условие (TLS-verify off, debug-режим, auth toggle)
остаётся UNKNOWN. Живой пример: LLM-ревьюер/билдер выдаёт `C-TLS`-подобные
условия на RabbitMQ-кейсах — ответить нечем. Спека §19 требует
«configuration overrides» в negative check; §12 — deployment config как
факт.

## Дизайн

Два новых `check=`-значения в `Condition.Params` — тот же канал, что
`symbol_present`/`exposure`:

- `check=config_flag` + `config_package` + `config_symbol` (`Type.Field`)
  + `insecure_value` — **код-уровневый knob**: присваивания полю
  (`tls.Config{InsecureSkipVerify: true}`, `x.InsecureSkipVerify = true`)
  ищутся в typed-индексе; значение резолвится из literal/const.
- `check=config_key` + `config_key` + `insecure_value` — **файл-уровневый
  ключ**: `exposure.FindKey` ищет ключ в yaml/env/toml/json репозитория.

### Семантика evaluator'а `ConfigFlag`

| Ситуация | Claim |
|---|---|
| присваивание со значением == insecure | TRUE (evidence) |
| присваивания есть, все ≠ insecure | FALSE-кандидат |
| присваивание нелитеральное | UNKNOWN «set via non-literal» |
| присваиваний нет, тип поля bool, insecure != zero | FALSE-кандидат «never set → Go zero value» |
| присваиваний нет, тип неизвестен/не bool | UNKNOWN |
| ключ найден в конфиге, value == insecure | TRUE |
| ключ не найден | UNKNOWN «может задаваться env/deployment вне репо» |

Zero-value правило — детерминистичная семантика Go (`SymbolFieldType`
даёт kind поля; bool + insecure_value="true" → неприсвоенное поле
гарантированно false). Это не эвристика.

Новый смысловой момент: FALSE-кандидаты без NV-стратегии пройдут
`NEGATIVE_CHECK` → `INSUFFICIENT_SCOPE` — claim виден, но вердикт не
опирается. Осознанно: «knob выставлен безопасно» — слабая негативная
позиция, пусть фиксируется как таковая.

### Кто создаёт условия

- `C-TLS-VERIFY` — supporting-шаблон в peer-driven паттерне
  (`crypto/tls` / `Config.InsecureSkipVerify`, insecure=true). Supporting,
  не mandatory: knob касается доверия к peer, не наличия уязвимости.
- LLM-промпт документирует оба check'а — предложенные knob'ы верифицируются
  `FindSymbol` до оценки (тот же контракт, что datum/pair symbols).

## Файлы

| Файл | Что |
|---|---|
| `domain.go` | `CheckConfigFlag`/`CheckConfigKey`, `ParamConfigPackage`/`ParamConfigSymbol`/`ParamConfigKey`/`ParamInsecure`, `ConfigAssignment`, `EvidenceGraph.ConfigFlags` + `Configuration` fills |
| `internal/goanalysis/config.go` (new) | `FieldAssignments`, `SymbolFieldType` |
| `internal/exposure/exposure.go` | `FindKey(root, key)` — generic ключ в конфигах |
| `states.go` | `collectConfigFlags` в CollectEvidence: verify knob → assignments/items → graph + evidence |
| `internal/evaluator/configflag.go` (new) | `ConfigFlag` evaluator |
| `patterns.go` | `C-TLS-VERIFY` supporting на peer-driven |
| `llm/exploit.go` | 2 строки промпта про check=config_flag/config_key |
| `testdata/tlsprod/`, `testdata/tlssafe/` | insecure=true / never-set фикстуры |

## Тесты / DoD

- `FieldAssignments`: composite-lit и AssignStmt RHS резолвятся (literal/const).
- `SymbolFieldType`: bool → "bool".
- Evaluator: все строки таблицы выше.
- e2e tlsprod → C-TLS-VERIFY TRUE; tlssafe → FALSE-кандидат.
- Живой прогон: GHSA-c5pq на продукт-референс → C-TLS-VERIFY с реальным
  ответом (они используют `amqp.DialTLS`?).
- suite + race зелёные.

## Не входит

- Конфиги k8s/helm/docker-compose (ScanRepo расширяем);
- секреты и шифрование-at-rest;
- runtime-флаги (CLI flags, os.Args);
- NV-стратегия для config FALSE-кандидатов (остаются INSUFFICIENT_SCOPE).
