package main

func getAuthority() []string       { return nil }
func getMeta() map[string][]string { return nil }

// defectSite indexes the guarded operand — the faulting shape the fix's
// `if len(authority) == 0` guard protects.
func defectSite() {
	authority := getAuthority()
	_ = authority[0]
}

// enabler checks the guarded value and returns — the operand is never
// indexed, dereferenced or called in this body.
func enabler() {
	mdata := getMeta()
	if len(mdata[":authority"]) == 0 {
		return
	}
	delete(mdata, "host")
	_ = len(mdata)
}

// aliasedDefect binds the guarded operand to a local and indexes the
// alias — the same faulting operation spelled differently.
func aliasedDefect() {
	mdata := getMeta()
	a := mdata[":authority"]
	_ = a[0]
}

// method is a receiver-qualified defect site.
type server struct{}

func (s *server) method() {
	authority := getAuthority()
	_ = authority[0]
}

func main() { defectSite(); enabler(); aliasedDefect(); (&server{}).method() }
