# Анализ похожих проектов и влияние на архитектуру

## 1. VEX Generation Toolset

Полезная идея: разделение `root cause discovery` и `call graph reachability`.

Фактическая цепочка:

```text
CVE -> references/fix commit -> diff -> LLM root cause functions -> call graph -> VEX
```

Что стоит взять:

- отдельный Root Cause Resolver;
- fix commit/diff как первичный источник механизма;
- distinction root cause vs functions added by the fix;
- explicit roles entrypoint/propagation/sink;
- отдельное представление reachability traces.

Что не стоит переносить:

- majority vote нескольких одинаковых LLM-вызовов как security proof;
- переход `reachable -> affected/update`, `unreachable -> unaffected/will_not_fix` как exploitability verdict.

Для нашего процесса root cause должен стать проверяемым объектом с Evidence, а reachability — только одним Mandatory Condition.

## 2. OWASP VulnReach

Полезная архитектура:

```text
SCA -> taint -> static reachability -> route exposure -> runtime -> correlation
```

Самая полезная идея — `EvidenceGraph`: raw outputs нормализуются в стабильный versioned contract перед LLM/reviewer.

Что стоит взять:

- EvidenceGraph;
- разделение raw tool results и normalized evidence;
- deterministic correlation layer;
- явные limitations;
- runtime evidence как усиление положительного утверждения;
- AI поверх структурированного evidence, а не поверх всего scanner JSON.

Что нужно изменить:

VulnReach в основном отвечает на reachability/exposure и использует классы вроде dynamically/static reachable, uncertain, not reachable. Для нашего trust model этого недостаточно: необходимо формально проверять конкретные exploit preconditions.

Главное отличие:

```text
VulnReach: vulnerable code reachable?
Наш контур: какие mandatory exploit conditions существуют и какие из них TRUE/FALSE/UNKNOWN?
```

## 3. amihit

На уровне README проект выглядит близко:

```text
CVE -> reachability -> taint -> exposure -> verdict
```

Но исходники показывают, что текущая реализация в основном эвристическая:

- Go reachability: import + AST/text call-site search, не полноценный call graph;
- taint: локальный variable tracking и proximity search;
- exposure: route regex/heuristics;
- verdict: `Reachable && TaintedInput && Exposed => EXPLOITABLE`, иначе эвристический score по direct/transitive, CVSS, active exploitation, PoC.

Что можно взять:

- дешёвые input-source patterns;
- route recognizers;
- некоторые AST/source helpers.

Все такие результаты должны иметь `EvidenceQuality=HEURISTIC` и не могут самостоятельно подтверждать safe FALSE.

## 4. govulncheck

Для Go это основной готовый компонент MVP.

Использовать для:

- affected module/package/symbol;
- call stacks;
- reachability evidence.

Не использовать как единственный источник exploitability verdict. Static analysis limitations и динамические механизмы должны сохраняться как limitations/UNKNOWN.

## 5. Итоговое изменение архитектуры

После анализа референсов целевая схема:

```text
Vulnerability
 -> Affected Resolver
 -> Root Cause Resolver
 -> RootCauseModel
 -> Exploit Condition Builder
 -> ExploitModel
 -> govulncheck + targeted source/SSA/config/runtime tools
 -> EvidenceGraph
 -> TRUE/FALSE/UNKNOWN
 -> deterministic Verdict
 -> Reviewer
```

Ключевая собственная ценность системы:

> `CVE + fix -> RootCause -> ExploitConditions -> Evidence по каждому Condition`.

Именно этот законченный контур не покрывается рассмотренными проектами.
