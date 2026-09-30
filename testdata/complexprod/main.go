package main

import (
	"os"

	"example.com/provenancedep/vuln"
)

func complexPure() { vuln.Value(complex(1, 2)) }

func complexExternal() { vuln.Value(complex(float64(os.Args[1][0]), 2)) }

func main() {
	complexPure()
	complexExternal()
}
