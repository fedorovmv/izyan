# real-yaml-http — GO-2021-0061 (yaml.v2 nested-anchors DoS)

- **Fix**: `go-yaml/yaml@bb4e33bf` — adds nesting/alias-limit tracking in the
  decoder (`decoder.unmarshal` → sink family: `Unmarshal`, `Decoder.Decode`).
- **Pin**: `gopkg.in/yaml.v2 v2.2.2` (fixed in `v2.2.3`) → affected by version.
- **Product**: `products/yaml-http` — `POST /config` body →
  `yaml.Unmarshal(body, &serviceConfig{})` at `main.go`.
- **Truth**: EXPLOITABLE. A remote client controls the entire YAML document
  reaching `Unmarshal`; deeply nested/aliased documents drive the
  stack-exhaustion panic the fix addresses. Guard: none (1 MiB body limit
  does not bound nesting depth — a few KB suffice).
- **Verified by hand**: fix-diff names `decoder.unmarshal`; advisory symbols
  (`Unmarshal`, `UnmarshalStrict`, `Decoder.Decode`) include the product's
  direct call; no validation between `io.ReadAll(r.Body)` and the sink.
