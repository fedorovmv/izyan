# real-yaml-http-fixed — GO-2021-0061 (version boundary)

- **Same product as real-yaml-http** (`products/yaml-http`) but pinned to
  `gopkg.in/yaml.v2 v2.4.0` — after the `v2.2.3` fix.
- **Truth**: NOT_AFFECTED — deterministic affected-chain result
  (`go list -m` resolves v2.4.0, outside `[0, 2.2.3)`).
