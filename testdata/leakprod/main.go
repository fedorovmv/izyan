package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// Product dials the service but never names the credential carrier nor
// reads its fields — the sensitive data has no product-side reader.
func main() {
	cfg := vuln.Dial("u", "p")
	fmt.Println(cfg.Username)
}
