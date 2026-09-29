# real-micro-xds — GO-2026-6441 / GHSA-qc2q-p7wx-3px3 (grpc xDS RBAC)

- Product `products/micro-xds`: gRPC server via `xds.NewGRPCServer` +
  xds credentials — configuration (incl. RBAC HTTP filters) is delivered
  by the xDS control plane at runtime.
- Advisory sinks `internal/xds/httpfilter/rbac`:
  `builder.ParseFilterConfig{,Override}`, `parseConfig` — internal pkg,
  registered via `httpfilter.Register(builder{})` in `init`, invoked from
  the xdsclient watcher pump on control-plane-delivered config.
- **Truth**: EXPLOITABLE for a control-plane-driven deployment — mixed-case
  header matchers bypass DENY evaluation. Reachability requires dep-internal
  edges through function-mediated registry + watcher callbacks.
- Analyzer: INCONCLUSIVE — honest. govulncheck reports `package-level`
  (no symbol path — its graph misses the watcher path); the "zero product
  references" falsifier is vacuous for internal symbols and no longer
  verifies. Remaining gap: registry-via-`Register()`-call and watcher/
  goroutine edges in dep-internal graphs (B24).
