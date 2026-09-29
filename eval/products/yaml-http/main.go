// yaml-http is a configuration ingest service: deployments POST a YAML
// document to /config, the service decodes it into the runtime config and
// serves the effective values back as JSON.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sync"

	"gopkg.in/yaml.v2"
)

type serviceConfig struct {
	Listen  string            `yaml:"listen"`
	Workers int               `yaml:"workers"`
	Env     map[string]string `yaml:"env"`
	Tags    []string          `yaml:"tags"`
}

type registry struct {
	mu  sync.Mutex
	cfg serviceConfig
}

func (r *registry) update(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	var next serviceConfig
	if err := yaml.Unmarshal(body, &next); err != nil {
		http.Error(w, "invalid yaml: "+err.Error(), http.StatusBadRequest)
		return
	}
	r.mu.Lock()
	r.cfg = next
	r.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (r *registry) current(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	_ = json.NewEncoder(w).Encode(r.cfg)
}

func main() {
	reg := &registry{cfg: serviceConfig{Listen: ":8080", Workers: 4}}
	http.HandleFunc("/config", reg.update)
	http.HandleFunc("/config/current", reg.current)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
