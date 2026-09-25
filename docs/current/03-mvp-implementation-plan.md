# План реализации MVP

## 1. Целевой сквозной сценарий

```text
CVE/GO/GHSA + Go repository snapshot
 -> affected dependency/version
 -> root cause
 -> exploit conditions
 -> govulncheck + targeted source analysis
 -> EvidenceGraph
 -> TRUE/FALSE/UNKNOWN
 -> deterministic verdict
 -> review
 -> report
```

## 2. Реализовывать вертикальными срезами

### Slice 1 — deterministic foundation

- domain model;
- ProductSnapshot;
- JSON persistence;
- vulnerability ingestion;
- affected resolver;
- verdict evaluator для `NOT_AFFECTED`.

Результат: уязвимая версия отсутствует -> `NOT_AFFECTED` без LLM.

### Slice 2 — govulncheck + evidence

- govulncheck adapter;
- Evidence/EvidenceGraph;
- manual `--root-cause`;
- manual `--exploit-model`;
- `SYMBOL_REACHABLE` claim.

Результат: нижнюю половину trust contour можно тестировать независимо от LLM.

### Slice 3 — source analysis

- find_symbol/find_callers/read_function/find_entrypoints;
- argument tracing;
- validation finder;
- negative verification.

Результат: первый кейс `reachable but mitigated` -> verified FALSE -> `NO_EXPLOIT_PATH_FOUND`.

### Slice 4 — Root Cause automation

- FixResolver;
- PatchProvider;
- LLM RootCause Resolver;
- RootCauseVerifier.

### Slice 5 — Exploit Model automation

- PatternRegistry;
- LLM ExploitModelBuilder;
- semantic ConditionEvaluator;
- gap-driven Planner.

### Slice 6 — review/report

- Reviewer;
- bounded repair loop;
- JSON/human report;
- tracker adapter.

## 3. Минимальные Go-пакеты

```text
internal/
  domain
  workflow
  vulnerability
  repository
  affected
  rootcause
  exploitmodel
  goanalysis
  evidence
  evaluator
  agent
  tools
  llm
  persistence
  report
```

## 4. Что писать первым

P0:

- domain;
- snapshot;
- persistence;
- affected resolver;
- evidence model.

P1:

- govulncheck adapter;
- source navigation;
- call-site analysis;
- argument tracing.

P2:

- fix diff + root cause.

P3:

- exploit model + condition evaluator.

P4:

- negative verification + reviewer.

P5:

- report + task tracker integration.

P6:

- remediation/runtime/advanced taint.

## 5. Test fixtures

Минимум:

- not-affected-version;
- reachable-exploitable;
- reachable-but-validated;
- constant/config-only;
- interface/dynamic-path;
- ambiguous-root-cause;
- tool-failure/build-failure.

Для каждого golden case сохраняются:

```text
rootcause.json
exploit_model.json
evidence_graph.json
claims.json
verdict.json
```

Сравниваются структуры, а не LLM prose.

## 6. Первый milestone

Поддержать:

```text
Go repository
+ known vulnerability
+ known vulnerable symbol
+ govulncheck
+ manual ExploitModel
+ targeted source analysis
+ TRUE/FALSE/UNKNOWN
+ deterministic Verdict
```

Это должно появиться раньше автоматического RootCause/ExploitModel reasoning.

## 7. Второй milestone

- automatic fix reference retrieval;
- RootCause Resolver;
- RootCauseVerifier.

## 8. Третий milestone

- automatic ExploitModel;
- Reviewer;
- bounded repair;
- final report.

После этого MVP является сквозным.

## 9. Метрики

Отдельно измерять:

- RootCause accuracy;
- Mandatory Condition recall;
- FALSE claim precision;
- exploitability verdict accuracy;
- false-safe count;
- INCONCLUSIVE rate;
- tool failure rate;
- average tool/LLM calls;
- evidence reproducibility.

Главный стоп-критерий — false-safe: ожидается EXPLOITABLE/INCONCLUSIVE, а система выдала `NO_EXPLOIT_PATH_FOUND`.

## 10. Не оптимизировать раньше времени

До eval dataset не добавлять сложную параллельную агентность, model routing, vector DB, generic workflow framework, full taint engine и runtime platform.

Каждая новая возможность должна отвечать на вопрос:

> Какой конкретный UNKNOWN Condition она позволяет перевести в TRUE или FALSE?
