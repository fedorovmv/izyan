package main

import (
	"fmt"

	"example.com/dep2/vuln"
)

// main passes a constant first key and a constant second key — the
// re-pick flag is dynamic, so both bindings stay reachable impls.
func main() {
	var repick bool
	fmt.Scan(&repick)
	fmt.Println(vuln.DispatchEither("vulnerable", "safe", "payload", repick))
}
