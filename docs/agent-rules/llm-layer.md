# LLM-слой и исследование CVE

Читать перед работой в `internal/llm/`, `internal/states/` и
`internal/cveanalysis/`.

- LLM выдаёт structured proposals; детерминистика верифицирует и
  авторитетна. LLM-claim никогда не вытесняет доказуемый det-результат.
- Автономное исследование CVE (`internal/cveanalysis`, `--cve-analysis
  <off|assist|verified>`): пайплайн `Researcher` → `StrategyPlanner` →
  `MechanismReviewer` формирует `Dossier` с дефектами (`RootCauses`),
  исключениями (`LocusExclusions`) и остатком на ручной аудит
  (`HumanRemainder`). Все гипотезы дефектов сопоставляются с AST/типами
  репозитория, а не принимаются на веру.
- Режим `--strict-llm`: при включении отсекает невалидный LLM-вывод с
  ошибкой, не допуская скрытого деградационного фолбэка.
- Бюджеты: `MaxLLMCalls`, planner ≤3 шага/condition внутри outer-loop
  ≤3 итераций; tool-miss → REJECTED + retry другим инструментом.
- Reviewer-промпт (`internal/llm/review.go`) содержит claim semantics —
  при изменении claim-полей обновляй её. Ключевое: FALSE на
  exploit-condition = safe-результат про продукт, не опровержение
  advisory; VERIFIED+demoted — ожидаемая история; демоция только по
  конкретному артефакту.
- Exec-инструменты (run_build/run_tests) — только за `--allow-exec`;
  без флага честный limitation, не скрытый запуск.
