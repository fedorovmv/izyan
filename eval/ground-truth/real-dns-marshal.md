# real-dns-marshal — GO-2020-0028 (unreachable-sink negative)

- Product `products/dns-marshal` imports `miekg/dns` only to construct
  and pack outbound NOTIFY messages (`SetNotify`, `Pack`). It never
  parses inbound zone text or wire data.
- **Truth**: NO_EXPLOIT_PATH_FOUND — advisory sinks
  (`ParseZone`/`NewRR`/`Unpack*` chain) are never invoked.
- Analyzer currently: INCONCLUSIVE — the affected sinks are partly
  unexported, so no direct product references cannot verify their
  absence. A closed dependency call graph is still missing.
