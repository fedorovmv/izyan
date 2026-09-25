package vuln

// Parse is a pretend vulnerable parser: fixed in v1.2.0.
func Parse(s string) string { return s }

// Parse2 is a second sink used to test grouped conditions.
func Parse2(s string) (string, error) { return s, nil }
