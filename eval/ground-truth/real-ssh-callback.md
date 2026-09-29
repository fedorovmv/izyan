# real-ssh-callback — GO-2024-3321

- Product `products/ssh-callback` configures `PublicKeyCallback` and
  accepts connections on `x/crypto v0.30.0` (< v0.31.0 fix).
- **Truth**: EXPLOITABLE — the server-authentication path that mishandles
  callback error semantics is live: untrusted clients drive
  `serverAuthenticate` with attacker-chosen public keys.
