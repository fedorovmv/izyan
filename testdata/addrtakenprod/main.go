package main

import "example.com/dep/vuln"

type reader struct {
	limit int
}

func (r *reader) setLimit(v int) {
	switch {
	case v < 0:
		v = 0
	case v > 1024:
		v = 1024
	}
	r.limit = v
}

func main() {
	r := &reader{}
	r.setLimit(5)
	// Taking the field's address opens a write path invisible to the
	// syntactic write-site scan — coverage must not be claimed.
	p := &r.limit
	_ = p
	vuln.Qos(r.limit, 0, false)
}
