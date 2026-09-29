package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// The product drives the dep's registry dispatch with a constant key and
// a constant payload — only the registered impl can run.
func main() {
	fmt.Println(vuln.Dispatch("real", "payload"))
}
