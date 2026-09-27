package main

import (
	"example.com/dep/vuln"
)

// One-sided variant: the switch bounds `size` only above — a negative
// size slips into the default and converts to a negative FileSize, so
// the written field is NOT bounded. No Covers may be emitted.

type fileSize int64

func (f fileSize) Bytes() int64 { return int64(f) }

const maxSize fileSize = 1024

type reader struct {
	n int
}

func (r *reader) setN(size int) {
	var fs fileSize
	switch {
	case fileSize(size) > maxSize:
		fs = maxSize
	default:
		fs = fileSize(size)
	}
	r.n = int(fs.Bytes())
}

func (r *reader) run() {
	vuln.Qos(r.n, r.n, false)
}

func main() {
	r := &reader{}
	r.setN(-5)
	r.run()
}
