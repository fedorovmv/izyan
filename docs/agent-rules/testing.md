# Тесты

- Каждое новое правило/эвристика — регрессионный тест. Фикстуры —
  мини-репозитории `testdata/<name>prod` со своим `go.mod` и dep-
  пакетом (`example.com/dep` и т.п.).
- Покрывай границы: negative-кейсы так же важны, как positive
  (напр., односторонняя граница ≠ гарда — `onesidedprod`;
  address-taken ≠ покрытие — `addrtakenprod`).
- Тесты на семантику, не на форму: проверяй результат claim/verdict,
  не текст совпадения где возможно.
- Полный прогон перед завершением: `go test ./...`; при изменении
  анализа — live-корпус `VA_PRODUCT_REPO=<r> go run ./cmd/analyzer
  eval --corpus eval/live-corpus.json` — цель 11/11, false-safe=0.
- Флаки недопустимы: LLM-недетерминизм в тестах отсекается
  (`--deterministic-only`, стабы `StaticSource`/manual root causes).
