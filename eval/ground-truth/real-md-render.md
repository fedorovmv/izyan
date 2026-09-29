# real-md-render — GO-2023-2074 (gomarkdown OOB read)

- **Fix**: `gomarkdown/markdown@14b16010c2ee` — bounds the citation-parser
  lookahead (`parser.isPrefixHeading`/`citation` family; affected symbols
  `Parser.Parse`, `Parser.Block`, `Parser.Inline`).
- **Pin**: `markdown v0.0.0-20230916125811-7478c230c7cd` (fix
  `v0.0.0-20230922105210-14b16010c2ee`) → affected.
- **Product**: `products/md-render` — `POST /render` body →
  `markdown.ToHTML(body, p, r)` → `parser.Parser.Parse` on user bytes.
- **Truth**: EXPLOITABLE. Peer-controlled markdown reaches `Parser.Parse`
  unconditionally; the OOB read is a pure input-shape bug, no product-side
  mitigation possible short of disabling citations.
- **Verified by hand**: `ToHTML` invokes the affected `parser` package path;
  advisory symbols cover the reachable parse entrypoints; input is a raw
  request body.
