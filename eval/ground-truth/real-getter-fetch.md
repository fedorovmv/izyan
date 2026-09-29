# real-getter-fetch — GO-2024-2800 (go-getter argument injection)

- **Fix**: `hashicorp/go-getter@268c11cae8cf0d` — sanitizes/validates the
  ref passed to `git` (`findRemoteDefaultBranch`, `GitGetter.clone`);
  affected `1.5.9–1.7.4`.
- **Pin**: `go-getter v1.7.3` → affected.
- **Product**: `products/getter-fetch` — `POST /fetch {"url": …}` →
  `getter.GetAny(dst, req.URL)`.
- **Truth**: EXPLOITABLE. The URL is fully peer-controlled; a crafted
  `git::` URL smuggles flag-shaped arguments into the git clone the getter
  performs. No allow-list/validation in the product.
- **Verified by hand**: `GetAny` is a declared affected symbol and is
  called directly; `req.URL` is JSON-decoded request input.
