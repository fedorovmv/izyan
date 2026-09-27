# Tool execution audit (tool_executions) — план фичи (gap-analysis #9)

Статус: done. Закрывает первый слой «Persistence»: `tool_executions` как
отдельная сущность по спеке §22.

## Проблема

Внешние инструменты (`git`, `go`, `govulncheck`, toolchain-пробы)
вызывались вразноброс через `exec.CommandContext` — кейс не мог
ответить «на каком инструменте и с какими аргументами получено это
доказательство». `Evidence.ToolVersion` объявлен, но не заполнялся.

## Решение

**Рекордер в context.** Shared-обёртки (кэшированные `gvRunner`/`goTool`
в scan/eval) создаются до кейса — рекордер нельзя пришить полем.
`toolaudit.WithRecorder(ctx)` ставит `Recorder{Sink}` в контекст
`analyzeCase` сразу после `store.Create`; все exec-точки вызывают
`toolaudit.Run(ctx, tool, version, dir, bin, env, args...)`, который
исполняет команду и пишет `ToolExecution` через рекордер из ctx —
запись ложится в граф того кейса, который сейчас исполняется. Нет
рекордера — просто не пишется (unit-тесты, ad-hoc вызовы).

**Запись** (`domain.ToolExecution`): tool, version (когда известна —
`ExecGoTool` тегирует `go`-прогоны версией toolchain'а), dir, args,
exit_code (-1 = never started / ctx kill), sha256 stdout+stderr,
duration_ms, error. Содержимое не дублируется — большие выводы
(govulncheck -json) уже лежат в evidence.Content, хэш привязывает
запись к нему.

**Покрытые точки:** `repository.command` (git rev-parse, go version,
go version -m на бинаре), `affected.runGo` (go list -m/-deps),
`goanalysis.ExecRunner` (govulncheck run + `-version`), toolchain-пробы
(version/env GOROOT/SDK). `packages.Load` — in-process вызов, не
subprocess; не записывается (граница).

**ToolVersion**: `runGovulncheck` теперь опрашивает `DBInfo` всегда —
его вывод («vulndb: …») пишется в `Evidence.ToolVersion` и переиспользуется
в not-covered limitation.

**Отчёт**: секция «Tool executions» — таблица tool@version, args, exit,
ms, sha-prefix.

## Побочный фикс

`analyzer eval` гонял корпус **с включённым LLM** — LLM-билдер exploit
model недетерминирован, корпус не мог служить регрессионным стопом
(поймали: два кейса флакнули на одном прогоне). Теперь eval по умолчанию
`--det-only`, `--with-llm` — opt-in для измерения LLM-варианта.

## Границы

- `Evidence.ToolVersion` заполнен только для govulncheck; `go list`
  evidence версию берёт из `ToolExecution.Version` по args, не
  денормализовано.
- `EvidenceGraph.Runtime []EvidenceID` — заполнен позже: snapshot-facts (GOOS/GOARCH/toolchain) и полный `go version -m` build info при `--binary` записываются как RUNTIME-evidence в `SnapshotProduct`.
- Env-ключи прогонов не записываются (могут содержать секреты из
  наследованного окружения) — записываются только args/tool/version.
- Повторный прогон кейса не сверяет хэши с прошлым (reproducibility
  diff — отдельный backlog-пункт).
