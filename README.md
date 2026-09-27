# Vuln Analyzer

Модуль на Go для автоматизированного анализа эксплуатируемости уязвимостей:
определяет применимость конкретной CVE/GO/GHSA к конкретному snapshot
продукта и формирует воспроизводимое техническое обоснование.

## Главный инвариант

Система не должна отвечать «уязвимость не эксплуатируется» только потому,
что LLM или статический анализатор не нашли путь.

```text
Vulnerability
  -> Root Cause
  -> Mandatory Exploit Conditions
  -> Evidence
  -> TRUE / FALSE / UNKNOWN
  -> deterministic Verdict
```

Если обязательное условие нельзя доказать как TRUE или FALSE, результат —
`INCONCLUSIVE`.

## Использование

```bash
go build -o vuln-analyzer ./cmd/analyzer

vuln-analyzer analyze \
  --repo /src/product \
  --vuln GO-2025-3595 \
  [--vuln-file advisory.osv.json] \
  [--osv-url https://api.osv.dev] \
  [--goos linux --goarch amd64] \
  [--build-tags tag1,tag2] \
  [--root-cause pkg/path.Symbol] \
  [--exploit-model exploit-model.json] \
  [--deterministic-only] \
  [--case-dir .vuln-analyzer]

vuln-analyzer scan \
  --repo /src/product \
  [--max-vulns 50] \
  [--deterministic-only] \
  [--case-dir .vuln-analyzer]

vuln-analyzer remediate \
  --repo /src/product --vuln GO-2025-3595 \
  [--apply] [--run-tests]   # без --apply — только план

vuln-analyzer analyze \
  --ticket ticket.json      # generic tracker intake (embedded/synth advisory)
```

`scan` опрашивает OSV по всем зависимостям (`go list -m all`), дёшево
отфильтровывает детерминистически-неаффектящие advisory и прогоняет
выжившие через полный пайплайн. Сводка — `<case-dir>/scan.json`.

Состояние кейса атомарно сохраняется после каждого перехода workflow в
`--case-dir`; отчёты пишутся в `<case-dir>/<case-id>/report.{json,md}`,
`openvex.json` и `cyclonedx.json` (обе — проекции вердикта, не источники).

## Статус реализации

Текущее состояние срезов MVP и ближайшие шаги:
[`docs/current/07-implementation-status.md`](docs/current/07-implementation-status.md).

## Проверка

```bash
go test ./...
go build ./cmd/analyzer
```

## Документация

- `docs/INDEX.md` — индекс и рекомендуемый порядок чтения.
- `docs/current/00-goals-scope.md` — цель, задачи, границы, verdicts, MVP.
- `docs/current/01-governing-spec.md` — главная спецификация системы.
- `docs/current/02-analyzer-agent-spec.md` — контракт Analyzer Agent.
- `docs/current/03-mvp-implementation-plan.md` — план по вертикальным срезам.
- `docs/current/04-go-skeleton-state-machine.md` — Go-контракты и state machine.
- `docs/current/05-reference-projects-analysis.md` — разбор референсов.
- `docs/current/06-decisions.md` — ключевые архитектурные решения и запреты.
- `docs/current/07-implementation-status.md` — статус срезов MVP.
- `docs/history/` — история эволюции решения.
