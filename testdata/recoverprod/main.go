package main

import (
	"os"

	"example.com/provenancedep/vuln"
)

func main() {
	defer func() { vuln.Value(recover()) }()
	panic(os.Args[1])
}
