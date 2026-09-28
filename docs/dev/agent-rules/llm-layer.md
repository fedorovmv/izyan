# LLM-слой

Читать перед работой в `internal/llm/` и `internal/states/`.

- LLM выдаёт structured proposals; детерминистика верифицирует и
  авторитетна. LLM-claim никогда не вытесняет доказуемый det-результат.
- Бюджеты: `MaxLLMCalls`, planner ≤3 шага/condition внутри outer-loop
  ≤3 итераций; tool-miss → REJECTED + retry другим инструментом.
- Reviewer-промпт (`internal/llm/review.go`) содержит claim semantics —
  при изменении claim-полей обновляй её. Ключевое: FALSE на
  exploit-condition = safe-результат про продукт, не опровержение
  advisory; VERIFIED+demoted — ожидаемая история; демоция только по
  конкретному артефакту.
- Exec-инструменты (run_build/run_tests) — только за `--allow-exec`;
  без флага честный limitation, не скрытый запуск.
