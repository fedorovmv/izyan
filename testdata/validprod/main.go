package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// Guard constrains the argument before the sink call.
func handle(s string) {
	if len(s) < 4 {
		return
	}
	fmt.Println(vuln.Parse(s))
}

func main() { handle("abcdef") }
