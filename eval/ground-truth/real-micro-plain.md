# real-micro-plain — GO-2026-6441 (no xds)

- Product `products/micro-plain`: plain `grpc.NewServer` — the xds tree
  (incl. `internal/xds/httpfilter/rbac`) is never imported; the blank
  imports registering the filter live in `google.golang.org/grpc/xds`.
- **Truth**: NOT_AFFECTED — affected package absent from the build graph.
- Analyzer: NOT_AFFECTED (deterministic) — correct and stronger than NEPF.
