# real-micro-plain-6443x — GO-2026-6443 / CVE-2026-84445 (locus-separated / signal-cleared)

- Product `products/micro-plain`: plain `grpc.NewServer` without xDS control plane.
- **govulncheck**: `REACHABLE` — false alarm on `HandleStreams` in `internal/transport`.
- **Analysis**:
  - The patch PR 9365 fixes a panic in `RouteAndProcess` (`authority[0]` index on empty slice).
  - The transport functions `HandleStreams` and `operateHeaders` only forward streams and perform preliminary validation; they do not contain the faulting operation.
  - With non-locus separation (expert basis or `--accept-locus-proposals`), L shrinks to `{RouteAndProcess}`.
  - `google.golang.org/grpc/internal/xds/server` is absent from the product build graph (`go list -deps`).
- **Truth**: NO_EXPLOIT_PATH_FOUND (Not Exploitable) — signal-cleared verified negative refuting govulncheck's reachable finding.
