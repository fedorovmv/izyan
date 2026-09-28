# Eval harness / regression corpus — план фичи (gap-analysis кандидат #8)

Статус: done. Закрывает первый слой пункта #8 приоритета и строку
«Метрики / eval harness» ([`dev/current/gap-analysis.md`](../current/gap-analysis.md) §3.7).

## Проблема

Каждая фича меняет поведение пайплайна на наборе механизмов, а регрессии
ловились только unit/e2e-тестами. Спека §9 требует измеримых метрик —
прежде всего **false-safe count**: кейс, где анализатор ответил
NOT_AFFECTED / NO_EXPLOIT_PATH_FOUND на вход, который safe не является.
Это стоп-критерий проекта; без корпуса он не измеряется.

## Дизайн

- `internal/eval` — типы корпуса и метрик (без зависимости на CLI):
  `Corpus{repo, cases[]}` — `repo` поддерживает env-экспансию
  (`${VA_PRODUCT_REPO}`; `--repo` флаг имеет приоритет),
  `Case{id, vuln|vuln_file, repo, root_causes,
  exploit_model, expect[], expect_claims{}}`, `Report{Metrics, Results}`,
  `Report.Record`, `Report.Markdown`.
- `vuln-analyzer eval --corpus <path> [--repo <path>] [--out md]
  [--json json] [common flags]` — прогоняет каждый кейс через полный
  `analyzeCase`, печатает таблицу и сводку.
- `expect` — список допустимых вердиктов. Диапазон (`["EXPLOITABLE",
  "INCONCLUSIVE"]`) — легитимная форма контракта: INCONCLUSIVE часто
  является правильным консервативным ответом, поэтому корпус кодирует
  приемлемость, а не единственный ответ.
- `expect_claims` — per-condition утверждения (`{"C-TLS-VERIFY":"TRUE"}`),
  ловят регрессии внутри вердикта.
- `root_causes` — строки `"pkg/path.Symbol"` или объекты
  `{package, symbol, role}` (object-форма нужна для method-субъектов
  `URI.String`, где строковый split «последняя точка» не работает).
  В corpus/CLI она проходит через новое поле `analyzeOpts.manualRC`.
- Пути в корпусе резолвятся относительно файла корпуса, не cwd.
- Exit code 1 при `false_safe>0 | expect_fail>0 | claims_fail>0 |
  errors>0` — пригодно для CI.
- `--case-dir` по умолчанию — per-run temp dir (корпус не мусорит в
  репо); для отладки падения — `--case-dir` на явный путь.

### Метрики

`total, errors, expect_pass, expect_fail, informational, verdicts{},
inconclusive, claims_fail, false_safe`. INCONCLUSIVE rate считается, но
не считается провалом — только распределением.

### Попутный фикс: reachability без govulncheck

`SymbolReachable` раньше при `!govulncheckRan` сразу отвечал UNKNOWN.
Теперь fallback в `libraryUsageVerdict` — тот же путь, что и для
«advisory not in DB»: module-usage evidence — легитимное позитивное
доказательство (продукт реально вызывает sink). FALSE-направление
усилено: FALSE-кандидат на «нет вызовов в модуль» теперь требует маркера
«usage scan ran» — иначе отсутствие данных ≠ отсутствие вызовов.
Инвариант «tool failure не фабрикует FALSE» сохранён.

## Корпус

`eval/corpus.json` + `eval/advisories/*.json` — синтетические OSV на
`example.com/dep` против фикстур `testdata/`:

| case | механизм | ожидание |
|---|---|---|
| unused-module | модуль не в графе | NOT_AFFECTED |
| const-arg-safe | константный аргумент | NO_EXPLOIT_PATH_FOUND (C-PEER-INPUT FALSE) |
| osargs-attacker | os.Args → sink | EXPLOITABLE |
| flag-input-unknown | flag → sink | INCONCLUSIVE |
| funcval-unsafe-false | func-value dispatch | EXPLOITABLE\|INCONCLUSIVE |
| gated-scope | build-tag-гейтед вызов | INCONCLUSIVE (GatedRefs) |
| cred-no-reader | INFO_LEAK без читателя | NO_EXPLOIT_PATH_FOUND |
| cred-reader | INFO_LEAK с читателем | EXPLOITABLE |
| tls-insecure / tls-safe | `C-TLS-VERIFY` claim | claims TRUE / FALSE |
| iface-dispatch | fmt.Stringer dispatch | INCONCLUSIVE |

Текущий прогон: 11 кейсов, 0 ошибок, 0 false-safe.

## Ограничения

- Фикстурные advisory не в OSV-БД: govulncheck-путь на них не работает;
  coverage фиксируется `not_in_db`/tool limitation. Живой корпус
  (продукт-референс × GHSA) описан отдельно — полные ID не хранятся в
  доке, набираются `scan`-ом.
- `expect` фиксирует приемлемость, а не «идеальный» вердикт — сужение
  диапазонов по мере роста точности — нормальный workflow корпуса.
- Метрики spec-уровня (root-cause accuracy, FALSE precision) требуют
  разметки ground truth сверх вердикта — следующий слой.
