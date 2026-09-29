# real-ssh-server — GO-2022-0968 (x/crypto/ssh pre-auth panic)

- **Fix**: `x/crypto@5770296d904e` (CL 368814) — bounds/panics-checks in
  `readCipherPacket` and kex message handling; affected symbols include
  `NewServerConn`, `Dial`, `NewClientConn`, cipher `readCipherPacket`s,
  kex `Client`/`Server` methods.
- **Pin**: `x/crypto v0.0.0-20211117183948-ae814b36b871` (fix
  `v0.0.0-20211202192323-5770296d904e`) → affected.
- **Product**: `products/ssh-server` — `net.Listen` + `Accept` →
  `ssh.NewServerConn(c, cfg)`; pre-auth handshake is peer-driven.
- **Truth**: EXPLOITABLE. The vulnerable packet handling runs during the
  unauthenticated handshake; any reachable SSH peer can send malformed
  negotiation packets to panic the process. No product-side mitigation.
- **Verified by hand**: `NewServerConn` called on every accepted conn;
  `Accept` is the peer boundary.
