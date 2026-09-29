package main

import (
	"fmt"
	"strings"

	"example.com/dyndep/dyn"
)

// main drives the dep's dynamic shapes: a func-value hop and an
// anonymous-interface dispatch — both mark the dep graph opaque.
func main() {
	out := dyn.RunWith(strings.ToUpper, "x")
	fmt.Println(out, dyn.AnonRunner(upper{}))
}

type upper struct{}

func (upper) Run() string { return "ok" }
