package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

// The guard exists but is wrapped in a config-reading conditional:
// it covers the sink only when STRICT_MODE is set — the analyzer must
// not treat it as an unconditional cover.
func main() {
	s := os.Args[1]
	if os.Getenv("STRICT_MODE") != "" {
		if len(s) > 8 {
			return
		}
	}
	fmt.Println(vuln.Parse(s))
}
