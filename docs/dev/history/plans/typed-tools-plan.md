# Typed tools (§17) — done

## Статус: реализовано

Все 17 инструментов §17 доступны в `llm.Tools`
(`internal/llm/tools.go`). Каждый вызов проходит через `Call`, считается
в `MaxToolCalls`, а результат регистрируется evidence — tool miss
возвращается модели как ошибка, а не как «фактов нет».

## Состав

| Группа | Инструменты | Примечание |
|---|---|---|
| Уязвимость | `get_vulnerability`, `get_advisory` | нормализованная запись кейса; `Vuln`-source для чужих advisory |
| Фикс | `get_fix_references`, `get_fix_diff` | `fix.Resolver` + `fix.Provider` (HTTP `.patch`/googlesource) |
| Модули | `get_module_version`, `get_dependency_graph` | resolved version кейса или `GoTool.ListModules` + `affected.DecodeModules` |
| Раннер | `run_govulncheck` | findings только по id/aliases кейса + `in_database` (Covers) — молчание БД ≠ путь не найден |
| Исходники | `read_function`, `read_source`, `search_source`, `find_symbol`, `find_references`, `find_callers`, `find_entrypoints`, `trace_argument`, `find_validations`, `scan_dynamic` | `read_source`/`search_source` — новые `Index`-методы, **confined в ix.Dir** (path escape отклоняется, dep-код в module cache не входит в поиск) |
| Exec | `run_build`, `run_tests` | **`AllowExec`-gated** (`--allow-exec`): исполняют код репозитория. Идут через `toolaudit.Run` → попадают в `tool_executions` аудит; провалы тоже пишутся evidence (`BUILD`/`TEST`) |

## Решения

- **Exec-гейт.** `go test ./...` исполняет тестовый код анализируемого
  репо — произвольное исполнение. По умолчанию выключено; флаг
  `--allow-exec` включает явно. Ошибка-отказ — честный tool miss.
- **Confinement.** `read_source` резолвит путь внутрь `Index.Dir`
  (`filepath.Rel` + отказ на `..`); `search_source` итерирует только
  файлы синтаксиса product-пакетов (свой код, не кэш модулей).
- **Toolchain.** Exec-инструменты наследуют `Index.Env` — сборка идёт
  под целевым toolchain (см. [`toolchain-plan.md`](toolchain-plan.md)).
- **`find_references`** — алиас поверх `SearchSymbol` (имя из §17).

## Не закрыто

- LLM-driven выбор инструментов — planner `GAP_ANALYSIS` пока
  детерминистичный; инструменты готовы, но агент их не вызывает
  самостоятельно за пределами `ClaimEvaluator`.
- `get_module_version` для stdlib/toolchain-модулей: резолвится через
  кейс-toolchain, не через `go list` (у stdlib нет module version).
