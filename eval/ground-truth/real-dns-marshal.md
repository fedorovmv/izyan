# real-dns-marshal — GO-2020-0028 (unreachable-sink negative)

- Product `products/dns-marshal` imports `miekg/dns` only to construct
  and pack outbound NOTIFY messages (`SetNotify`, `Pack`). It never
  parses inbound zone text or wire data.
- **Truth**: NO_EXPLOIT_PATH_FOUND — advisory sinks
  (`ParseZone`/`NewRR`/`Unpack*` chain) are never invoked.
- Analyzer: NO_EXPLOIT_PATH_FOUND — first dispatch/provenance-falsified
  negative against a *reachable-baseline* case in the new batch.
