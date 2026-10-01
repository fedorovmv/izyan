# real-micro-plain-6443 — GO-2026-6443 / CVE-2026-84445 (unassisted baseline)

- Product `products/micro-plain`: plain `grpc.NewServer` without xDS control plane.
- The advisory declares three symbols: `http2Server.HandleStreams` and `http2Server.operateHeaders` in `google.golang.org/grpc/internal/transport`, and `RouteAndProcess` in `google.golang.org/grpc/internal/xds/server`.
- **govulncheck**: `REACHABLE` — finds call chain from `main` to `HandleStreams`.
- **Truth**: Not exploitable in reality, but without non-locus basis/proposals, the full declared set is in L. `HandleStreams` is reachable in the trace, so the conservative analyzer evaluates `C-LOCUS` as TRUE (matching govulncheck's conservative positive).
