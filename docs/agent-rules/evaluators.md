# Evaluator-цепочка и claims

Читать перед работой в `internal/evaluator/` и
`cmd/analyzer/main.go` (регистрация).

- Цепочка — first-match wins; `Custom` обязан быть последним
  (обрабатывает unroutable shapes). Порядок: `SymbolReachable`,
  `ServerTransportInput`, `ArgumentOrigin`, `Validation`, `Exposure`,
  `Authentication`, `ConfigFlag`, `Presence`, `VersionFact`,
  `Platform`, `Custom`.
- `SymbolReachable`: проверяет как стандартную достижимость символов,
  так и defect locus условия (`C-LOCUS`) через `evalLocus`.
  При отсутствии пакета дефекта в графе сборки выставляет
  `FalsifierLocusPackageAbsent`; при наличии пакета, но недостижимости
  функции дефекта в callgraph продукта — `FalsifierLocusFunctionUnreached`.
  Оба являются строгими валидными фальсификаторами для safe-negative вердикта.
- `ArgumentOrigin`: INPUT_CONSTRAINT falsified by guards только при
  `unknown == 0` по всем flows и полном покрытии mutable-аргументов;
  const/GENERATED не требуют Covers. При отсутствии внешних и неизвестных
  источников и поступлении только compile-time констант/GENERATED генерирует
  `FalsifierConstantOrGeneratedInput`; для чтения локальных конфигурационных
  файлов (`OriginConfiguration`) — `FalsifierTrustedInfrastructure`.
- `Authentication` никогда не FALSE: отсутствие auth-wiring в скане
  ≠ отсутствие auth (per-handler/gateway/deployment вне скана).
- LLM claim-fallback — только в конце GAP_ANALYSIS после
  det-evaluators и planner-actions (`internal/states/gap.go`);
  пропускает уже-FALSE. В `EvaluateConditions` fallback'а нет
  намеренно — LLM-TRUE иначе вытесняет доказуемый det-FALSE.
- Repair только ослабляет (demotion): high → demotion, medium/low —
  advisory. Демоция VERIFIED-FALSE → UNKNOWN легитимна только по
  артефакту, названному в `problem` и записанному как ослабляющий для
  этого claim'а: dynamic-маркер или site `file.go:line` из nv.Limitations
  (точное file:line-совпадение), traced origin из flows, claim-linked
  evidence-id, либо dangling evidence-ссылка (claim- или nv-evidence;
  Structural поднимает finding по обеим). Не считаются артефактом:
  `required_check` (желаемое, не найденное), nv.Notes (позитивный итог и
  dismissed-маркеры — «unrelated go:linkname pragma(s) ignored»),
  content evidence (dismissed-маркеры, benign-прованс), validations и
  Covers (покрытие, не опровержение), explanation/limitations claim'а
  (rationale/process-текст; rejected finding не может цитировать сам
  себя). Без артефакта — advisory concern, claim стоит. История
  falsifier+verification сохраняется и видна в отчёте
  (`VERIFIED (demoted)`).
- Gap-planner действия per-arg (`f.Arg`); `ReplaceDataFlow` матчит
  (cond, sink, arg). `verifyHops=16` — перетрейс на том же бюджете
  глубины, иначе deep-резолвленные flows дают ложные CONTRADICTED.
