package main

import (
	"fmt"
	"os"

	"example.com/provenancedep/vuln"
)

type externalString struct{}

func (externalString) String() string { return os.Args[1] }

func main() { vuln.Parse(fmt.Sprint(externalString{})) }
