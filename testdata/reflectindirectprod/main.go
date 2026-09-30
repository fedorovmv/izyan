package main

import (
	"os"
	"reflect"

	"example.com/provenancedep/vuln"
)

func main() {
	s := os.Args[1]
	vuln.Parse(reflect.Indirect(reflect.ValueOf(&s)).Interface().(string))
}
