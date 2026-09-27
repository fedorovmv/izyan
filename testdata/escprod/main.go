package main

import (
	"fmt"
	"html"
	"os"

	"example.com/dep/vuln"
)

// An escape transform sits between source and sink: it is recorded as
// provenance (security-relevant, not modeled as a guard).
func main() {
	s := html.EscapeString(os.Args[1])
	fmt.Println(vuln.Parse(s))
}
