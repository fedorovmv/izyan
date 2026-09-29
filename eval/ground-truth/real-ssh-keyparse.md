# real-ssh-keyparse — GO-2022-0968 (negative usage)

- **Same advisory/pin as real-ssh-server**, different product:
  `products/ssh-keyparse` imports `golang.org/x/crypto/ssh` only for
  `ParseAuthorizedKey`/`FingerprintSHA256` — the authorized_keys file
  audit never opens a connection.
- **Truth**: NO_EXPLOIT_PATH_FOUND. The vulnerable code paths
  (`NewServerConn`, kex/cipher packet handling) are never invoked — no
  call path exists, transitively or directly. Module present, affected
  version, affected package imported: the negative is about *usage*, not
  presence — exactly the case manifest scanners cannot express.
