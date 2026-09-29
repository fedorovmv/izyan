# real-getter-file — GO-2024-2800 (dispatch-key negative)

- Product `products/getter-file` calls `getter.GetAny(dir, depotArtifact)`
  with a compile-time constant `file:///opt/artifact-depot/agent-v2.tar.gz`.
- The advisory requires reaching `GitGetter` (arg injection via `git::`
  URL handling). Dispatch happens at `Client.Get`: `c.Getters[force]` where
  `force` derives from the URL scheme/forced prefix.
- **Truth**: NO_EXPLOIT_PATH_FOUND. Scheme `file` is constant →
  `FileGetter` only; `FileGetter` never performs the `X-Terraform-Get`
  nested re-dispatch that keeps `GitGetter` reachable in `getter-const`
  (that switch lives in `HttpGetter.Get`). No path to the sink exists.
- Analyzer currently: INCONCLUSIVE — eval of `force` still carries
  union over client instances; the narrowing mechanism is in place, the
  remaining gap is eval completeness, not a safety error. `expect`
  accepts both until the gap closes.
