package main

import (
	"fmt"

	"example.com/dep/vuln"
)

func main() {
	m := vuln.MapClaims{}
	if !m.VerifyAudience() {
		fmt.Println("invalid audience")
		return
	}
	fmt.Println(vuln.ParseClaims(), vuln.ParseMapClaims())
}
