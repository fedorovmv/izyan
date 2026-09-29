# real-unix-stat — GO-2022-0493 (usage-negative)

- Same advisory/pin as `real-unix-access`, product `products/unix-stat`
  imports `golang.org/x/sys/unix` for `Statfs`/`Geteuid` only — it never
  calls `Faccessat`.
- **Truth**: NO_EXPLOIT_PATH_FOUND — the advisory declares a single
  exported symbol, the product references none, so the zero-refs
  falsifier is non-vacuous and verification is sound.
- Analyzer: NEPF — first sound verified negative against a real dep
  where govulncheck sees only package-level usage.
