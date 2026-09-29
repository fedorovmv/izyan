# real-jwt-auth — GO-2020-0017 (jwt-go aud bypass) — MISSING-CALL trap

- **Mechanism**: jwt-go's `MapClaims.Valid()` validates `exp/iat/nbf` but
  **never calls `VerifyAudience`** — `aud` is ignored by construction.
  The advisory's declared sink (`MapClaims.VerifyAudience`) is therefore
  unreachable *by design*: nobody calls it.
- **Product**: `products/jwt-auth` — `jwt.ParseWithClaims(raw, MapClaims{}, kf)`
  on a Bearer token, relying on library validation.
- **Truth**: EXPLOITABLE — a token minted for another audience is accepted.
- **Analyzer caveat**: the reach+input model inverts for missing-call
  advisories — govulncheck silence on `VerifyAudience` yields a VERIFIED
  reach-FALSE → NO_EXPLOIT_PATH_FOUND against a true EXPLOITABLE. Kept
  informational (no expect) as a live demonstration; tracked as B21.
