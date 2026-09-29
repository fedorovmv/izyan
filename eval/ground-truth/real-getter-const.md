# real-getter-const — GO-2024-2800 (conditional protocol switch)

- **Same advisory/pin as real-getter-fetch**, different product:
  `products/getter-const` calls `getter.GetAny(dir, releaseArtifact)` where
  `releaseArtifact` is a package-level string constant.
- **Truth for static triage**: INCONCLUSIVE. The outer URL is constant,
  but the default `HttpGetter` accepts `X-Terraform-Get` or a
  `terraform-get` meta tag from the HTTP response. Its `Get` method
  calls `Get(dst, source)` with that server-provided value; the default
  getter set includes Git, so a protocol switch can reach `GitGetter`.
  Whether an attacker controls that server response is a deployment
  trust question. A safe verdict from the constant outer URL would be
  false-safe.
- **Verified in dependency source**: `get_http.go` reads the header/meta
  value and re-dispatches through `Get`; the product does not set
  `XTerraformGetDisabled`.
