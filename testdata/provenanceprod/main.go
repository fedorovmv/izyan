package main

import (
	"example.com/provenancedep/vuln"
)

func fileSource() { vuln.Parse(vuln.Load("literal.txt")) }

func pureWrapper() { vuln.Parse(vuln.Identity("literal")) }

func main() {
	fileSource()
	pureWrapper()
}
