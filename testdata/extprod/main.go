package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

// Argument flows from os.Args -> attacker controlled.
func main() {
	fmt.Println(vuln.Parse(os.Args[1]))
}
