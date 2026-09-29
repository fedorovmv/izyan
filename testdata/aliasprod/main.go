package main

import (
	"fmt"

	"example.com/dep4/vuln"
)

// The product instantiates ExtraRunner — reachable as a dispatch target
// exactly when the alias-mutated registry is not narrowed to its
// literal contents.
func main() {
	var _ vuln.Runner = &vuln.ExtraRunner{}
	fmt.Println(vuln.DispatchAlias("vulnerable"))
}
