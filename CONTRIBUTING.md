# Contributing to Izyan

Thank you for your interest in contributing to **Izyan**!

## Core Invariants

Izyan is a deterministic Go vulnerability analyzer designed to weed out false positives without compromising safety. All contributions must respect these fundamental invariants:

1. **`false-safe = 0`**: Never produce an unsafe negative verdict without rigorous proof. A negative verdict (`NO_EXPLOIT_PATH_FOUND`) requires a verified `Falsifier` on a mandatory condition.
2. **Absence of proof is not proof of absence**: If an exploit path is not found, the fallback verdict is `INCONCLUSIVE` (or `UNKNOWN`), never `NOT_AFFECTED` or `NO_EXPLOIT_PATH_FOUND`.
3. **Deterministic verification overrides AI**: Compiler analysis and static reachability checks are authoritative. LLM outputs are treated strictly as structured proposals.
4. **Reproducibility**: Analysis results, evidence IDs, and dossiers must be deterministic and verifiable.

## Development Setup

1. Requires Go 1.25 or later.
2. Clone the repository:
   ```bash
   git clone https://github.com/fedorovmv/izyan.git
   cd izyan
   ```
3. Build the binary:
   ```bash
   go build -o izyan ./cmd/izyan
   ```

## Local Validation

Before submitting a Pull Request, ensure that all checks pass:

```bash
# Check code formatting
gofmt -l .

# Run static analysis
go vet ./...

# Run the test suite
go test ./...
```

For changes affecting the evaluator or negative verification, verify the real benchmark corpus:
```bash
go run ./cmd/izyan eval --corpus eval/corpus-real.json -j 4
```
Ensure that `false-safe = 0` is strictly maintained.

## Commit Message Guidelines (Conventional Commits)

This repository uses automated release tagging based on **Conventional Commits**:

* `feat: ...` or `feat(scope): ...` triggers a **minor** release (`v0.1.0` -> `v0.2.0`).
* `fix: ...`, `fix(scope): ...`, `perf: ...`, `refactor: ...` triggers a **patch** release (`v0.1.0` -> `v0.1.1`).
* `feat!: ...` or commit body containing `BREAKING CHANGE:` triggers a **major** release (`v1.0.0` -> `v2.0.0`).

Please format your commit messages accordingly.

## Pull Request Guidelines

* Keep diffs focused and minimal.
* Include unit tests for bug fixes and new features.
* Avoid unrelated changes in the same PR.
* Zero internal corporate paths, private credentials, or API keys in tracked files.
