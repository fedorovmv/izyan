package main

import (
	"fmt"

	"example.com/dep/vuln"
)

// The product drives the dep's peer-fed codec: the vulnerable parser
// readRecord can only be reached inside the library's read path, fed by
// whatever the remote endpoint sends.
func main() {
	c, err := vuln.Connect("broker:5672")
	if err != nil {
		panic(err)
	}
	n, _ := c.Next()
	fmt.Println(n, vuln.Fixed())
}
