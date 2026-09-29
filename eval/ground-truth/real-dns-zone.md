# real-dns-zone — GO-2020-0028 (miekg/dns zone-parser DoS)

- **Fix**: `miekg/dns v1.0.10` — fixes panic on malformed zone data in the
  scanner (`NewRR`, `ParseZone`, `ReadRR`, `setTA`).
- **Pin**: `miekg/dns v1.0.9` → affected.
- **Product**: `products/dns-zone` — `POST /zone/import` zone text →
  `dns.ParseZone(strings.NewReader(body), origin, …)`.
- **Truth**: EXPLOITABLE. The uploaded zone file is fully peer-controlled
  and fed verbatim into `ParseZone`; crafted records panic the parser.
- **Verified by hand**: `ParseZone` is a declared affected symbol; the
  reader carries request bytes; error channel drains every token.
