# real-yaml-const — GO-2021-0061 (const-input negative)

- Product `products/yaml-const` unmarshals a build-time constant YAML
  document; no user/wire input reaches `yaml.Unmarshal`.
- **Truth**: NO_EXPLOIT_PATH_FOUND — the attacker-control mandatory
  condition is false: the document bytes are constant, so no crafted
  input can drive the panic path.
- Analyzer currently: INCONCLUSIVE — const-input falsification not yet
  proven end-to-end; `expect` accepts both.
