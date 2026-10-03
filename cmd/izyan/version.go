package main

import (
	"fmt"
	"runtime/debug"
)

var (
	// Version is set via -ldflags="-X main.Version=..." at build time.
	Version = "dev"
	// Commit is set via -ldflags="-X main.Commit=..." at build time.
	Commit = "none"
	// Date is set via -ldflags="-X main.Date=..." at build time.
	Date = "unknown"
)

func init() {
	if bi, ok := debug.ReadBuildInfo(); ok {
		if Version == "dev" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			Version = bi.Main.Version
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if Commit == "none" {
					Commit = s.Value
				}
			case "vcs.time":
				if Date == "unknown" {
					Date = s.Value
				}
			}
		}
	}
}

func printVersion() {
	if Commit != "none" {
		fmt.Printf("izyan %s (commit %s, built %s)\n", Version, Commit, Date)
	} else {
		fmt.Printf("izyan %s\n", Version)
	}
}
