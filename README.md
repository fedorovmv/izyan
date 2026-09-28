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

vuln-analyzer analyze --repo /src/product --vuln GO-2025-3595
vuln-analyzer scan    --repo /src/product
vuln-analyzer remediate --repo /src/product --vuln GO-2025-3595 [--apply]
vuln-analyzer analyze --ticket ticket.json   # generic tracker intake
```

Полный справочник команд, флагов и выходных артефактов —
[`docs/cli.md`](docs/cli.md).

## Проверка

```bash
go test ./...
go build ./cmd/analyzer
```

## Документация

- `docs/INDEX.md` — индекс и рекомендуемый порядок чтения.
- `docs/goals-scope.md` — цель, задачи, границы, verdicts, MVP.
- `docs/dev/specs/governing-spec.md` — главная спецификация системы.
- `docs/dev/specs/analyzer-agent-spec.md` — контракт Analyzer Agent.
- `docs/dev/decisions/architecture-decisions.md` — ключевые архитектурные решения и запреты.
- `docs/cli.md` — справочник команд и флагов.
- `docs/architecture.md` — архитектура: конвейер, средства, модель данных.
- `docs/how-it-works.md` — гарантии, вердикты, известные границы.
- `docs/dev/history/` — история эволюции решения.
