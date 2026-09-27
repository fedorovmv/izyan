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
	s string `mapstructure:"prefetch_input"`
}

type reader struct {
	s string
	n int
}

// fileSize mirrors the rm6m local type: the compared var and the
// sanitized var differ, and the default branch converts the
// range-bounded compared var.
type fileSize int64

func (f fileSize) Bytes() int64 { return int64(f) }

const (
	defaultSize fileSize = 0
	maxSize     fileSize = 1024
)

func loadCfg() config {
	// decode via tag machinery: no literal write sites exist.
	var c config
	_ = os.Getenv("unused")
	return c
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

// setN mirrors setPrefetchSize: the switch bounds the *compared* var
// (size) on both sides while every clause assigns the sanitized var fs —
// the default converts the range-gated size. The field write itself is
// wrapped in an accessor call (fs.Bytes()), not a bare ident.
func (r *reader) setN(size int) {
	var fs fileSize
	switch {
	case size < 0:
		fs = defaultSize
	case fileSize(size) > maxSize:
		fs = maxSize
	default:
		fs = fileSize(size)
	}
	r.n = int(fs.Bytes())
}

func (r *reader) run() {
	fmt.Println(vuln.Parse(r.s))
	vuln.Qos(r.n, r.n, false)
}

func main() {
	cfg := loadCfg()
	r := &reader{}
	r.setS(cfg.s)
	r.setN(2048)
	r.run()
}
