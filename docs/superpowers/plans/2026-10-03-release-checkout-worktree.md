# Safe Release Checkout & Worktree Snapshotting Implementation Plan

## Overview
When analyzing a repository with ticket metadata or command-line parameters, if a release is identified (e.g. `24.2`, `v1.5.0`, `release/2026.1`), the analyzer can automatically resolve the target git tag or branch, and check it out in an isolated, temporary `git worktree`. This ensures:
1. The developer's main working tree is completely safe (uncommitted changes untouched, current branch unchanged).
2. The analysis runs on the exact commit associated with the release in the ticket.
3. The worktree is cleanly and reliably removed upon completion.
4. If the current checkout (`HEAD`) is already at the target commit, no redundant worktree is created.
5. If the release cannot be found in git, a helpful error is produced without corrupting any state.

## Proposed Changes

### `internal/repository`
- Add `ResolveRef(ctx context.Context, repoPath, releaseOrRef string) (resolvedRef string, commitSHA string, err error)`:
  - Checks if `releaseOrRef` is already a valid commit or ref via `git rev-parse --verify --quiet <ref>^{commit}`.
  - Tries standard release tag conventions:
    - `v` + `releaseOrRef` (e.g. `24.2` -> `v24.2`, `v24.2.0`)
    - `release/` + `releaseOrRef`
    - `rel-` + `releaseOrRef`
    - `tags/` + `releaseOrRef`
  - Scans `git tag -l` for fuzzy matching (case-insensitive, leading `v` trimming).
  - Returns the resolved ref name and commit SHA.
- Add `NewWorktree(ctx context.Context, repoPath, commitOrRef string) (worktreePath string, cleanup func(), err error)`:
  - Creates a temporary directory via `os.MkdirTemp("", "izyan-worktree-*")`.
  - Runs `git worktree add --detach <tempdir> <commitOrRef>`.
  - Returns `worktreePath` and a `cleanup` closure that invokes `git worktree remove --force <tempdir>` and `os.RemoveAll(tempdir)`.
- Unit tests in `internal/repository/service_test.go`:
  - Test ref resolution on temporary git repository with various tag formats.
  - Test worktree creation and cleanup.

### `cmd/izyan`
- Flags in `runAnalyze`:
  - `--checkout-release`: boolean flag, default false. "resolve release/tag from ticket or --release and run analysis in an isolated git worktree"
  - `--release <ver>`: string flag, default "". "explicit release tag, branch, or commit to analyze (overrides ticket release)"
- In `runAnalyze`:
  - If `--release` is passed, `o.ticketRel = *releaseFlag`.
  - If `o.checkoutRelease` is true and `o.ticketRel != ""`:
    - Resolve ref in `o.repo`.
    - If current `HEAD` commit equals resolved commit, analyze in place without creating worktree.
    - Otherwise, create isolated worktree, defer cleanup, update `o.repo = worktreePath`.
    - Add limitation / note to evidence graph.
- Integration tests in `cmd/izyan/intake_cli_test.go`:
  - Test `--checkout-release` on a temporary git repository with tags and verify that the target commit is analyzed and the worktree is cleaned up.

### Documentation
- `docs/cli.md`: document `--checkout-release` and `--release`.
- `docs/dev/gap-analysis.md`: sync status.

## Verification Plan
1. `go test -v ./internal/repository/...`
2. `go test -v ./cmd/izyan/... -run "TestCLI_CheckoutRelease"`
3. `gofmt -s -w .`
4. `go vet ./...`
5. `go test -count=1 ./...`
