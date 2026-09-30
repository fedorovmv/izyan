package main

import (
	"fmt"

	"example.com/recvdep/vuln"
)

// The product feeds the decoder a compile-time constant and invokes the
// method through a function value — the receiver travels as arg0 and its
// provenance must resolve across separately loaded package instances.
func main() {
	dec := vuln.NewDecoder([]byte("constant"))
	fn := vuln.Decoder.Unmarshal
	fmt.Println(fn(dec))
}
