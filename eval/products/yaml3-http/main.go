// yaml3-http ingests policy documents POSTed to /policy and decodes them
// into a typed struct with gopkg.in/yaml.v3.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	"gopkg.in/yaml.v3"
)

type policy struct {
	Name    string    `yaml:"name"`
	Actions []string  `yaml:"actions"`
	Parent  yaml.Node `yaml:"parent"`
}

func ingest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var p policy
	if err := yaml.Unmarshal(body, &p); err != nil {
		http.Error(w, "invalid yaml: "+err.Error(), http.StatusBadRequest)
		return
	}
	_ = json.NewEncoder(w).Encode(p)
}

func main() {
	http.HandleFunc("/policy", ingest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
