# real-yaml3-const — GO-2022-0603 (constant input)

- Same vulnerable yaml.v3 version and advisory as `real-yaml3-http`.
  The product calls `yaml.Unmarshal` once with a build-time constant
  document and never reads a file, request, environment variable, or
  service response into the parser.
- **Truth**: NO_EXPLOIT_PATH_FOUND. The advisory's panic requires crafted
  input; no attacker-controlled bytes reach the only product call site.
  The fixed document is ordinary valid YAML and contains no external
  input hook.
- **Verification**: the grouped exploit model contains one affected
  symbol, `Unmarshal`. Both traced arguments resolve to CONSTANT; the
  negative verifier re-traces the only product call site and returns
  VERIFIED. The paired `real-yaml3-http` case supplies request bytes
  to the same API and remains EXPLOITABLE.
