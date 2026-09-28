package main

import (
	"fmt"

	"example.com/dep/vuln"
	"example.com/kbprod/kv"
)

// kv.Get is a config-reading helper the default knowledge base does not
// know: without a --knowledge extension the argument origin stays
// UNKNOWN; with one naming it a CONFIGURATION source it resolves.
func main() {
	fmt.Println(vuln.Parse(kv.Get("secret-key")))
}
