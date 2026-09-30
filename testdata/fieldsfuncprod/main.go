package main

import (
	"os"
	"strings"

	"example.com/provenancedep/vuln"
)

func main() {
	parts := strings.FieldsFunc("literal", func(r rune) bool {
		return r == []rune(os.Args[1])[0]
	})
	vuln.Parse(parts[0])
}
