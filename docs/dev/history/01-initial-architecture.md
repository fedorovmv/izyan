# Исходная архитектура до анализа OSS-референсов

Этот документ фиксирует первоначальный вариант решения, чтобы изменения governing spec были прослеживаемы.

## Исходная задача

Vulnerability task содержит CVE/уязвимость. Самая трудная часть remediation SLA — определить эксплуатируемость относительно кода продукта и обосновать решение. Если vulnerability exploitable и есть fixed dependency — обновить; при несовместимости изменить код.

## Исходный trust contour

```text
Task Tracker
 -> Vulnerability Intake
 -> Advisory Enricher
 -> Exploitability Analyzer
     LLM builds exploit model
     deterministic tools collect evidence
 -> Evidence Evaluator
 -> Verdict
 -> optional Remediation Agent
```

Главная идея уже была evidence-first: LLM строит гипотезы и план проверки, а deterministic gate выводит финальный verdict.

## ExploitabilityCase

Основной объект должен был хранить vulnerability, product snapshot, exploit model, evidence, claims, reviews и verdict.

## Exploit conditions

CVE description преобразуется в набор required preconditions. Каждое условие имеет `TRUE/FALSE/UNKNOWN`.

Примеры:

- affected version exists;
- vulnerable symbol included in build;
- call path exists;
- external entrypoint exists;
- attacker controls relevant argument;
- no sanitizer/mitigation blocks condition;
- additional CVE-specific constraints.

## Go analysis

Предлагалось использовать:

- `go list -m -json all`;
- `go list -deps -json`;
- `go mod graph`;
- `govulncheck -json ./...`;
- `golang.org/x/tools/go/packages`;
- SSA/callgraph;
- targeted source analysis.

`govulncheck` рассматривался как evidence source, а не final decider.

## Verdicts

- `NOT_AFFECTED`;
- `EXPLOITABLE`;
- `NO_EXPLOIT_PATH_FOUND`;
- `INCONCLUSIVE`.

Ключевое правило: простой факт «path not found» недостаточен для `NO_EXPLOIT_PATH_FOUND`.

## Reviewer

Второй LLM должен был проверять unsupported claims, missed preconditions/callers, patch interpretation и слабые negative conclusions, но не повторять анализ с нуля.

## Remediation

Отдельный workflow:

```text
EXPLOITABLE
 -> fixed version
 -> go get / go mod tidy
 -> build/tests/govulncheck
 -> compatibility repair if needed
 -> repeat vulnerability analysis
```

## Что изменено в актуальной версии

После анализа VEX Generation Toolset/VulnReach/amihit:

- root cause выделен в отдельный gate;
- появился versioned EvidenceGraph;
- `govulncheck` окончательно выбран базовым Go reachability source;
- собственный full taint/callgraph исключён из MVP;
- EvidenceQuality сделан явным;
- confidence полностью исключён из verdict logic.
