package main

import (
	"fmt"
	"os"

	"example.com/dep/vuln"
)

// Mirrors the rm6m/Qos shape: the sink argument is a struct field read,
// populated through a setter whose caller passes a config-derived value.
// Provenance must hop field write sites -> setter param -> caller arg
// -> cfg.s field -> os.Getenv -> CONFIGURATION.

type config struct {
	s string
}

type reader struct {
	s string
}

func loadCfg() config {
	return config{s: os.Getenv("PREFETCH_INPUT")}
}

// setS clamps the stored value: every case sanitizes or rejects, so the
// field is bounded regardless of what the caller passed — a sanitize
// guard at the field's write site rather than before the sink.
func (r *reader) setS(s string) {
	switch {
	case len(s) > 8:
		s = "bounded"
	case s == "":
		return
	}
	r.s = s
}

func (r *reader) run() {
	fmt.Println(vuln.Parse(r.s))
}

func main() {
	cfg := loadCfg()
	r := &reader{}
	r.setS(cfg.s)
	r.run()
}
