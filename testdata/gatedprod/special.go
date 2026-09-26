//go:build special

package main

import "example.com/dep/vuln"

// gatedCall only compiles under -tags special; a reachability FALSE that
// never saw this file cannot claim verified coverage.
func gatedCall() string {
	return vuln.Parse("x")
}
