# Цель, задачи и границы проекта

## Цель

Создать модуль на Go для автоматизированного анализа уязвимостей из task tracker, который определяет применимость и эксплуатируемость конкретной CVE/GO/GHSA для конкретного snapshot продукта и формирует воспроизводимое техническое обоснование.

Система должна отвечать не только на вопросы «есть ли уязвимая зависимость?» и «вызывается ли уязвимая функция?», а на главный вопрос:

> Выполняются ли в конкретной версии продукта все обязательные условия эксплуатации конкретной уязвимости?

## Основные задачи

- получить и нормализовать сведения об уязвимости;
- зафиксировать анализируемый commit, build context и зависимости продукта;
- детерминированно проверить affected version/package/build;
- определить root cause: конкретные функции/методы и механизм ошибки;
- построить минимальный набор обязательных условий эксплуатации;
- собрать проверяемые доказательства по каждому условию;
- классифицировать каждое условие как `TRUE`, `FALSE` или `UNKNOWN`;
- получить итоговый verdict только детерминированным Go-кодом;
- выполнить review наиболее критичных утверждений;
- сформировать отчёт для task tracker и аудита;
- сохранить состояние так, чтобы анализ можно было воспроизвести без истории LLM-чата.

## Verdicts

- `NOT_AFFECTED` — уязвимая версия/компонент неприменимы к snapshot продукта.
- `EXPLOITABLE` — все обязательные условия эксплуатации подтверждены.
- `NO_EXPLOIT_PATH_FOUND` — хотя бы одно обязательное условие доказанно ложно и отрицательное доказательство прошло дополнительную проверку.
- `INCONCLUSIVE` — существенное условие осталось `UNKNOWN` или анализ ограничен инструментами/конфигурацией.

## Что не является доказательством эксплуатируемости

- CVSS;
- EPSS;
- CISA KEV;
- наличие PoC;
- факт присутствия зависимости;
- факт импорта пакета;
- сам по себе найденный call path;
- высокий confidence модели.

Эти сигналы могут влиять на priority/SLA, но не на exploitability verdict.

## Главный trust boundary

```text
LLM reasoning
    -> typed tools
    -> Evidence
    -> Conditions / Claims
    -> deterministic Verdict
```

LLM используется для семантических задач: анализ patch/fix, построение exploit conditions, выбор следующей проверки, интерпретация кода и review. LLM не является источником фактов и не устанавливает финальный verdict.

## Границы MVP

В MVP входят:

- Go repositories;
- Go Vulnerability Database / OSV;
- affected resolver;
- fix/reference resolver;
- Root Cause Resolver;
- Exploit Condition Builder;
- `govulncheck` как основной Go-specific reachability source;
- targeted source analysis;
- argument provenance;
- поиск релевантной validation;
- EvidenceGraph;
- `TRUE/FALSE/UNKNOWN` claims;
- negative-check для сильного `FALSE`;
- Reviewer;
- deterministic Verdict Engine;
- JSON + human-readable report.

Не входят в MVP:

- универсальный taint engine;
- собственный полный call-graph engine вместо `govulncheck`;
- RAG по всему репозиторию;
- vector DB;
- сложный multi-agent workflow;
- автоматическое исправление кода и создание PR;
- полноценная runtime instrumentation platform.

## Критерий успеха

Успехом считается не красивый LLM-ответ и не простое совпадение с экспертом, а воспроизводимая цепочка:

```text
Root Cause
 -> Exploit Conditions
 -> Evidence
 -> Claims
 -> Verdict
```

Критическая ошибка — необоснованный safe verdict (`NO_EXPLOIT_PATH_FOUND`) для фактически эксплуатируемой или неразрешённой уязвимости.
