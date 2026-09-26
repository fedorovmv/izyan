package main

import (
	"crypto/tls"

	"example.com/dep/vuln"
)

const skipVerify = true

func insecure() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
}

func alsoInsecure(c *tls.Config) {
	c.InsecureSkipVerify = skipVerify
}

func main() { _ = insecure(); _ = vuln.Parse }
