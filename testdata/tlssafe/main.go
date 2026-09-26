package main

import (
	"crypto/tls"

	"example.com/dep/vuln"
)

func safe() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13}
}

func main() { _ = safe(); _ = vuln.Parse }
