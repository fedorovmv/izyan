package main

import "fmt"

var (
	// Version is set via -ldflags="-X main.Version=..." at build time.
	Version = "dev"
	// Commit is set via -ldflags="-X main.Commit=..." at build time.
	Commit = "none"
	// Date is set via -ldflags="-X main.Date=..." at build time.
	Date = "unknown"
)

func printVersion() {
	if Commit != "none" {
		fmt.Printf("izyan %s (commit %s, built %s)\n", Version, Commit, Date)
	} else {
		fmt.Printf("izyan %s\n", Version)
	}
}
