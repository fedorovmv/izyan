package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
	"example.com/dep5/driver"
)

// Two linked modules: the dep subject is invoked only with a constant
// (safe), while the dep5 subject is invoked solely inside the dependency
// with process input flowing through.
func main() {
	fmt.Println(vuln.Parse("<fixed>"))
	fmt.Println(driver.Drive(os.Args[1]))
}
