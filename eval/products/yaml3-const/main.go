package main

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

const baseline = "name: stable\nactions: [read]\n"

type policy struct {
	Name    string   `yaml:"name"`
	Actions []string `yaml:"actions"`
}

func main() {
	var p policy
	if err := yaml.Unmarshal([]byte(baseline), &p); err != nil {
		panic(err)
	}
	fmt.Println(p.Name)
}
