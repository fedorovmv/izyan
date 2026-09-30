package main

import (
	"fmt"
	"html"

	"example.com/dep/vuln"
)

var keyC = make(chan byte, 1)

// An escape transform sits between source and sink: it is recorded as
// provenance (security-relevant, not modeled as a guard). The input
// itself is unresolvable — bytes arrive through a channel whose send
// sites are not inventoried — so the origin stays UNKNOWN.
func main() {
	s := html.EscapeString(string(<-keyC))
	fmt.Println(vuln.Parse(s))
}
