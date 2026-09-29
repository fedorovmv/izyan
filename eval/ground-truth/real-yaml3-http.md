# real-yaml3-http — GO-2022-0603

- Product `products/yaml3-http` unmarshals POSTed policy bodies with
  `yaml.v3` pinned to `v3.0.0-20210107192922-496545a6307b` (before the
  `3.0.0-20220521…` fix pseudo-version).
- **Truth**: EXPLOITABLE — attacker-controlled YAML reaches
  `yaml.Unmarshal`; anchor/alias node cycles drive the panic path.
