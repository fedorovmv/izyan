package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// The vulnerable symbol is invoked through a function value — static call
// graphs may miss this path; negative verification must not verify FALSE.
func main() {
	f := vuln.Parse
	fmt.Println(f("x"))
}
