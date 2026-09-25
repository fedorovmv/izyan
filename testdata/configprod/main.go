package main

import (
	"flag"
	"fmt"

	"example.com/dep/vuln"
)

// The sink argument comes from a command-line flag: a configuration-
// controlled value. Whether an attacker can influence it depends on the
// deployment trust boundary, so attacker control must stay UNKNOWN.
var in = flag.String("in", "default", "input")

func main() {
	flag.Parse()
	fmt.Println(vuln.Parse(*in))
}
