package vuln

// Parse is a pretend vulnerable parser: fixed in v1.2.0.
func Parse(s string) string { return s }

// Parse2 is a second sink used to test grouped conditions.
func Parse2(s string) (string, error) { return s, nil }

// Qos is a pretend int-arg sink — the rm6m shape: prefetch values bounded
// by setter-side clamps before reaching the call.
func Qos(count, size int, global bool) {}
