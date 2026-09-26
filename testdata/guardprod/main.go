package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

// The sink frame has no guard; the only caller validates the argument.
func sink(s string) {
	fmt.Println(vuln.Parse(s))
}

func main() {
	data := os.Args[1]
	if data == "" {
		return
	}
	sink(data)
}
