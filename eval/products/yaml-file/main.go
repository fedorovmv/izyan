// yaml-file is an operator-facing CLI that loads the service's YAML
// configuration from a local file and prints the normalized settings.
// The document comes from the host filesystem, not from the network.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

type serviceConfig struct {
	Listen  string            `yaml:"listen"`
	Workers int               `yaml:"workers"`
	Env     map[string]string `yaml:"env"`
	Tags    []string          `yaml:"tags"`
}

func load(path string) (serviceConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return serviceConfig{}, err
	}
	var cfg serviceConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return serviceConfig{}, fmt.Errorf("parse %s: %w", path, err)
	}
	return cfg, nil
}

func main() {
	path := flag.String("config", "service.yaml", "path to the YAML config")
	flag.Parse()
	cfg, err := load(*path)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("listen=%s workers=%d env=%d tags=%v\n",
		cfg.Listen, cfg.Workers, len(cfg.Env), cfg.Tags)
}
