package main

import (
	"fmt"

	"example.com/dep3/vuln"
)

// main registers impls under runtime keys — index-writes the literal-
// table scan cannot see; DispatchLate must stay unrestricted, so every
// instantiated impl remains a dispatch target.
func main() {
	vuln.Register("plugin", &vuln.SafeRunner{})
	vuln.Register("extra", &vuln.RealRunner{})
	fmt.Println(vuln.DispatchLate("plugin", "payload"))
}
