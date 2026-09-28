# Evaluator-цепочка и claims

Читать перед работой в `internal/evaluator/` и
`cmd/analyzer/main.go` (регистрация).

- Цепочка — first-match wins; `Custom` обязан быть последним
  (обрабатывает unroutable shapes). Порядок: `SymbolReachable`,
  `ServerTransportInput`, `ArgumentOrigin`, `Validation`, `Exposure`,
  `Authentication`, `ConfigFlag`, `Presence`, `VersionFact`,
  `Platform`, `Custom`.
- `ArgumentOrigin`: INPUT_CONSTRAINT falsified by guards только при
  `unknown == 0` по всем flows и полном покрытии mutable-аргументов;
  const/GENERATED не требуют Covers.
- `Authentication` никогда не FALSE: отсутствие auth-wiring в скане
  ≠ отсутствие auth (per-handler/gateway/deployment вне скана).
- LLM claim-fallback — только в конце GAP_ANALYSIS после
  det-evaluators и planner-actions (`internal/states/gap.go`);
  пропускает уже-FALSE. В `EvaluateConditions` fallback'а нет
  намеренно — LLM-TRUE иначе вытесняет доказуемый det-FALSE.
- Repair только ослабляет (demotion): high → demotion, medium/low —
  advisory. Демоция VERIFIED-FALSE → UNKNOWN легитимна, но история
  falsifier+verification сохраняется и видна в отчёте
  (`VERIFIED (demoted)`).
- Gap-planner действия per-arg (`f.Arg`); `ReplaceDataFlow` матчит
  (cond, sink, arg). `verifyHops=16` — перетрейс на том же бюджете
  глубины, иначе deep-резолвленные flows дают ложные CONTRADICTED.
