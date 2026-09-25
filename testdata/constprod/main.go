package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// Product calls the vulnerable symbol with a compile-time constant:
// ATTACKER_CONTROL is provably FALSE.
func main() {
	fmt.Println(vuln.Parse("<fixed-not-attacker-controlled>"))
}
