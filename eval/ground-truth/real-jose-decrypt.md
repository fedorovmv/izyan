# real-jose-decrypt — GO-2023-2409 (jose2go p2c DoS)

- **Fix**: `jose2go@a4584e9dd7128` — caps the PBES2 iteration count read
  from the JWE header (`p2c`) inside `decrypt`; affected symbols
  `Decode`, `DecodeBytes`, `Pbse2HmacAesKW.*`, `decrypt`.
- **Pin**: `jose2go v1.5.0` (fixed `v1.5.1-0.20231206…`) → affected.
- **Product**: `products/jose-decrypt` — `POST /intake` token body →
  `jose.Decode(token, sharedKey)`; `Decode` dispatches JWE → `decrypt`.
- **Truth**: EXPLOITABLE. `p2c` is attacker-supplied inside the JWE header;
  a huge value makes the key-derivation loop spin for minutes — a
  single-request DoS. No product-side bound exists (the count lives
  inside the token, not in a call argument).
- **Verified by hand**: `Decode` is a declared affected symbol called
  directly on peer input.
