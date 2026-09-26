package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// render calls URI.String through the fmt.Stringer interface — a static
// search for the concrete method sees the interface, not the impl.
func render(u vuln.URI) string {
	var s fmt.Stringer = u
	return s.String()
}

func main() { fmt.Println(render(vuln.URI{Raw: "amqp://x"})) }
