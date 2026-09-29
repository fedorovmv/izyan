package main

import (
	"fmt"

	"example.com/dep6/vuln"
)

// The product writes into the dependency's exported registry — the
// mutation site lives in a different packages.Load graph, so pointer
// identity on types.Object would miss it.
func main() {
	vuln.Registry["runtime"] = &vuln.ExtraRunner{}
	fmt.Println(vuln.DispatchExported("runtime"))
}
