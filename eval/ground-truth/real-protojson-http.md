# real-protojson-http — GO-2024-2611

- Product `products/protojson-http` decodes POSTed JSON with
  `protojson.Unmarshal` on protobuf `v1.32.0` (< v1.33.0 fix).
- **Truth**: EXPLOITABLE — attacker-controlled JSON reaches the
  unmarshal loop; the `{"[field]":` infinite-loop input is directly
  deliverable over the wire.
