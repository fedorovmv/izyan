// yaml-const loads the embedded baseline config — the YAML document is a
// build-time constant, never parsed from user input.
package main

import (
	"fmt"

	"gopkg.in/yaml.v2"
)

const baseline = `listen: ":8080"
workers: 4
env:
  REGION: us-east
tags: [baseline]`

type serviceConfig struct {
	Listen  string            `yaml:"listen"`
	Workers int               `yaml:"workers"`
	Env     map[string]string `yaml:"env"`
	Tags    []string          `yaml:"tags"`
}

func load() serviceConfig {
	var cfg serviceConfig
	if err := yaml.Unmarshal([]byte(baseline), &cfg); err != nil {
		panic(err)
	}
	return cfg
}

func main() {
	cfg := load()
	fmt.Printf("listen=%s workers=%d\n", cfg.Listen, cfg.Workers)
}
