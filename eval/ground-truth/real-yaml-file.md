# real-yaml-file — GO-2021-0061 (config-origin variant)

- **Same advisory/pin as real-yaml-http**, different product:
  `products/yaml-file` — CLI that reads a local YAML config
  (`os.ReadFile` → `yaml.Unmarshal`).
- **Truth**: not exploitable over the network — the document comes from
  the host filesystem (operator-controlled config). Formally the analyzer
  can only bound provenance to CONFIGURATION (deploy-dependent), so the
  honest verdict is INCONCLUSIVE, matching the corpus expectation.
