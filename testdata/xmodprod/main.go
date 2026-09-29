package main

import (
	"fmt"
	"os"

	"example.com/dep5/driver"
)

// The product drives the sibling-package caller with process input —
// dep5/deep.Sink is reachable through a dep-internal cross-package edge
// even though the product never names it, and its argument is external.
func main() {
	fmt.Println(driver.Drive(os.Args[1]))
}
