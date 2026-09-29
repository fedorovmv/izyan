# real-unix-access — GO-2022-0493 (positive, linux-only)

- Product `products/unix-access` calls `unix.Faccessat(AT_FDCWD, path,
  R_OK, AT_EACCESS)` on the mount-policy security check — the vulnerable
  wrapper directly, on x/sys pre-fix pseudo-version. `goos=linux` per-case.
- **Truth**: EXPLOITABLE-shaped reachability — the advisory's only
  declared symbol (`Faccessat`, exported) is invoked by the product.
  Whether the wrong access verdict harms depends on deployment; the
  reach claim is provable.
- Also exercises multi-module advisory resolution: GO-2022-0493 carries
  stdlib + `golang.org/x/sys` affected entries; resolver must pick x/sys.
