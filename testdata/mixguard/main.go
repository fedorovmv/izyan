package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

func sink(s string) {
	fmt.Println(vuln.Parse(s))
}

// guarded rejects empty input before calling sink.
func guarded(data string) {
	if data == "" {
		return
	}
	sink(data)
}

// unguarded reaches sink on a path with no validation — partial caller
// coverage must NOT justify a FALSE validation claim.
func unguarded() {
	sink(os.Getenv("UNSAFE_INPUT"))
}

func main() {
	guarded(os.Args[1])
	unguarded()
}
