package driver

import "example.com/dep5/deep"

// Drive invokes the subject from a sibling package of the same module —
// the argument flows straight through so provenance reaches the product
// call site.
func Drive(s string) string { return deep.Sink(s) }
