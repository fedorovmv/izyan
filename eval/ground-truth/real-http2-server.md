# real-http2-server — GO-2023-2102 (stdlib toolchain boundary)

- **Advisory shape**: OSV lists `stdlib` first, then `golang.org/x/net`;
  the analyzer's module resolution takes the Go entry → stdlib, judged by
  the *toolchain* version, not a dep pin.
- **Product**: `products/http2-server` — `http.Server.ListenAndServeTLS`
  on the analysis toolchain go1.26 (fixed: 1.20.10/1.21.3).
- **Truth**: NOT_AFFECTED — the toolchain predating fixes would be
  affected; 1.26 is past both fixed ranges.
