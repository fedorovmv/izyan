# real-getter-const — GO-2024-2800 (negative product)

- **Same advisory/pin as real-getter-fetch**, different product:
  `products/getter-const` calls `getter.GetAny(dir, releaseArtifact)` where
  `releaseArtifact` is a package-level string constant.
- **Truth**: NO_EXPLOIT_PATH_FOUND. Argument injection requires attacker
  control of the fetched URL; the product always fetches its pinned
  release artifact — no path carries peer input to the sink.
- **Verified by hand**: only one call site; both arguments statically
  resolvable (`MkdirTemp` dir, const URL); no indirection.
