package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// main drives the dep's validation pipeline — sibling check calls inside
// Valid are on the product path; the never-invoked VerifyAud member is a
// missing call, not dead code.
func main() { fmt.Println(vuln.ParseClaims(), vuln.ParseMapClaims()) }
