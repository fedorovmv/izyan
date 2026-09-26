package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// Product reads the exported credential field — a product-side reader
// makes the retained sensitive data observable.
func main() {
	cfg := vuln.Dial("u", "p")
	fmt.Println(cfg.Password)
}
