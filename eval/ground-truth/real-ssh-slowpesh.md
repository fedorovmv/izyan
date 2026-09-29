# real-ssh-slowpesh — GO-2025-3487 (slow-handshake DoS)

- Same product as `real-ssh-server` (`ssh.NewServerConn` listener), dep
  pinned to `v0.34.0` (< v0.35.0 fix). Advisory mixes exported entry
  symbols with unexported handshake internals.
- **Truth**: EXPLOITABLE — untrusted clients drive the server handshake;
  the slow-handshake goroutine exhaustion path is reachable.
