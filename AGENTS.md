# vuln-analyzer

Go vulnerability analyzer. Определяет применимость и эксплуатируемость
уязвимости в конкретном снапшоте продукта, сохраняя неопределённость и
избегая небезопасных отрицательных выводов.

## Главные инварианты

* Отсутствие найденного exploit path не доказывает его отсутствие.
* `FALSE` допустим только при наличии `Falsifier` и успешной negative verification.
* `NO_EXPLOIT_PATH_FOUND` допустим только для VERIFIED falsifier на mandatory-условии.
* `NOT_AFFECTED` определяется только детерминистической affected-цепочкой.
* `UNKNOWN` — валидный терминальный результат; не дожимай claim ради определённого verdict.
* Детерминистические проверки авторитетнее LLM. LLM создаёт только structured proposals.
* `VERIFIED` означает, что конкретный falsifier проверен с учётом dynamic markers и coverage, а не что «проверено всё».
* VERIFIED-FALSE может быть демотирован в `UNKNOWN`; история проверки должна сохраняться в отчёте.

## Репозиторий

* Go-код: `internal/`.
* CLI: `cmd/analyzer`.
* Тестовые mini-repo: `testdata/`.
* Канонический backlog: `docs/dev/current/gap-analysis.md`.
* Live corpus: `eval/README.md` и `eval/live-corpus.json`.
* Приватные локальные пути не коммитить.

## Правила изменения

Каждое функциональное изменение должно обновлять:

* `docs/dev/current/gap-analysis.md`: выполненное → §4, оставшееся → §5;
* `eval/README.md`, если изменилось наблюдаемое поведение анализатора.

Один коммит — одно логическое изменение. Не создавать временные `.md`, `.out`
и другие артефакты в корне репозитория.

Перед завершением задачи:

```bash
gofmt
go vet ./...
go test ./...
```

Для изменений анализатора также должен проходить live corpus с `false-safe=0`.

## Дополнительные правила

Тематические инструкции находятся в `docs/dev/agent-rules/`.
Читай только относящиеся к текущей задаче.

| Область                              | Правила                                          |
| ------------------------------------ | ------------------------------------------------ |
| архитектура и доменная модель        | `architecture.md`                                |
| изменение Go-кода                    | `coding.md`                                      |
| тесты, фикстуры, live corpus         | `testing.md`                                     |
| отрицательные выводы и безопасность  | `security.md`                                    |
| CLI, схемы и внешние интерфейсы      | `api.md`                                         |
| метрики, аудит и отчётность          | `observability.md`                               |
| `internal/goanalysis`                | `provenance-and-bounds.md`, `dynamic-markers.md` |
| `internal/evaluator`, `cmd/analyzer` | `evaluators.md`                                  |
| `internal/llm`, `internal/states`    | `llm-layer.md`                                   |
| документация и закрытие backlog      | `docs-sync.md`                                   |

Если задача затрагивает несколько областей, прочитай все соответствующие правила.
Не загружай остальные без необходимости.
