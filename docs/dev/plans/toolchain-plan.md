# Target Go toolchain — план фичи (runtime/stdlib advisory)

Статус: done (первый слой). Закрывает дыру «анализ на локальном Go при релизе,
собранном другой версией» — критично для `std`/`toolchain`/`cmd`
адвизори, где уязвимый код живёт в GOROOT, а не в зависимости.

## Проблема

`affected.resolver` уже сравнивает version-ranges stdlib-адвизори с
`ReleaseGoVersion` (build info бинаря → `--release-go-version`), но вся
остальная машинерия работает на **локальном toolchain**:

- `packages.Load`/`Index` резолвит stdlib-символы в локальный GOROOT —
  `FindSymbol`, `SearchSymbol`, `SensitiveFields`, `ModuleInternalReach`
  для `crypto/tls`, `net/http` и т.п. читают чужую версию исходников.
- `govulncheck -mode source` type-checks stdlib из локального GOROOT.
- Evidence не фиксирует, на каком Go его собрали (стык с #9 audit).

`govulncheck -mode binary` (`--binary`) авторитетен для reachability
(читает build info артефакта), но source-анализ остаётся локальным.

## Решения (обсуждено)

- **Все три стратегии провижинга**, в порядке приоритета (CI может быть
  оффлайн):
  1. `sdk` — уже установленный `~/sdk/goX.Y.Z` (golang.org/dl), оффлайн;
  2. `gotoolchain` — `GOTOOLCHAIN=goX.Y.Z` env, Go ≥1.21 качает в
     module cache; GOROOT находится через `go env GOROOT` под тем же env;
  3. `docker` — образ `analyzer+target-sdk`, весь анализ внутри
     контейнера (devops-режим; toolchain анализатора ≠ toolchain
     проверки — бинарь собран любым Go, проверки идут контейнерным `go`).
- **Источник версии**: build info бинаря (`--binary`) →
  `--release-go-version` → `corpus.go_version` (eval-кейс). Приоритет
  бинаря уже реализован в `repository.Service`.
- **Семантика отказа**: целевой toolchain недоступен → limitation +
  для stdlib-адвизори source-анализ не делается под локальной версией
  молча — фиксируется, что символы искались в другой версии GOROOT.
  Никогда не производить FALSE на чужой версии без пометки.

## Дизайн

```go
// internal/toolchain
type Toolchain struct {
    Version string   // "1.21.13" — целевая; "" = local
    GoBin   string   // "go" | ~/sdk/go1.21.13/bin/go | ...
    Env     []string // GOTOOLCHAIN=..., GOROOT=... для subprocess
    GOROOT  string   // host-путь для source-резолва (Index.GOROOT)
    Mode    string   // local | sdk | gotoolchain | docker
}
Resolve(ctx, want, cur string) (Toolchain, []string /*limitations*/)
```

- `resolve`: `want==""||want==cur` → local; иначе пробует sdk
  (`~/sdk/go<ver>/bin/go` существует) → gotoolchain (`GOTOOLCHAIN=go<ver>
  go version` пробный вызов — проверяет, что Go умеет скачать) → fail
  с limitation (docker — не подмена toolchain, а другой режим запуска,
  см. ниже).
- Wiring: `analyzeOpts.toolchain`; `buildEnv(build)` расширяется env
  toolchain'а; `ExecGoTool`/`ExecRunner` принимают `GoBin`+Env;
  `Index{GOROOT}` — `packages.Load` с `GOROOT`/`GOTOOLCHAIN` env, stdlib
  исходники читаются из целевого GOROOT.
- Provenance: evidence `Tool`/`Command` получают суффикс `(go1.21.13)`;
  `ProductSnapshot.ToolchainMode` + фактический resolved version в
  кейс (после `go<ver> version`).
- Corpus: `Case.GoVersion` → прогон фикстур под конкретным toolchain;
  `--release-go-version` уже в common flags.
- Docker-режим: `eval`/`analyze` не меняются — контейнер собирается как
  `golang:<target>` + скопированный бинарь анализатора; документируем
  `docker build -f eval/Dockerfile --build-arg GO_VERSION=1.21.13`.
  Внутри контейнера toolchain=local(=target) — вся машинерия работает
  без спец-кода. Analyzer и target Go разделены по построению.

## Ограничения / границы

- `govulncheck` сам — отдельный бинарь; source-mode под `GOTOOLCHAIN`
  использует целевой toolchain через go/packages, но версия
  govulncheck должна быть совместима (фиксируем в tool_executions).
- `ModuleInternalReach` для stdlib никогда не vendored — с целевым
  GOROOT внутримодульные цепочки стдлиб теперь резолвятся корректно
  (раньше — локальные исходники).
- Скачивание через GOPROXY требует сети один раз; оффлайн-CI —
  предустановленные `~/sdk/*` или docker-образ.
- macOS/linux only (GOPATH-совместимые пути); Windows — best effort.
