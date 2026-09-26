package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

// The attacker-controlled argument reaches the sink through a three-hop
// parameter chain — deeper than the default provenance climb bound
// (maxTraceHops=2). The first pass leaves the origin UNKNOWN; the
// gap-analysis loop must deepen the trace and resolve EXTERNAL.
func main() {
	level1(os.Args[1])
}

func level1(a string) {
	level2(a)
}

func level2(b string) {
	level3(b)
}

func level3(c string) {
	fmt.Println(vuln.Parse(c))
}
