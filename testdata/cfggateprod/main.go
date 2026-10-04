package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

// The guard exists but is wrapped in a config-reading conditional:
// it covers the sink only when STRICT_MODE is set — the analyzer must
// not treat it as an unconditional cover.
func main() {
	s := os.Args[1]
	if os.Getenv("STRICT_MODE") != "" {
		if len(s) > 8 {
			return
		}
	}
	fmt.Println(vuln.Parse(s))
}

type FeatureConfig struct {
	EnableVulnerableFeature bool
}

var appCfg = FeatureConfig{
	EnableVulnerableFeature: false,
}

func callVulnerableGated() {
	if appCfg.EnableVulnerableFeature {
		vuln.Parse("vulnerable")
	}
}

func callVulnerableZeroValue() {
	var emptyCfg FeatureConfig
	if emptyCfg.EnableVulnerableFeature {
		vuln.Parse("vulnerable-zero")
	}
}

func callVulnerableDynamic() {
	if os.Getenv("DYNAMIC_FEATURE") == "true" {
		vuln.Parse("dynamic")
	}
}
