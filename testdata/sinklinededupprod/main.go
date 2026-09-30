package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

func main() {
	fmt.Println(vuln.Parse("safe"), vuln.Parse(os.Args[1]))
}
