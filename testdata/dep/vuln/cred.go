package vuln

// PlainAuth is a pretend credential carrier — the GHSA-27gv mechanism:
// sensitive data retained in exported fields any code holding the
// struct can read.
type PlainAuth struct {
	Username string
	Password string
}

// Dial returns a connection config carrying the credential struct.
func Dial(user, pass string) PlainAuth {
	return PlainAuth{Username: user, Password: pass}
}
