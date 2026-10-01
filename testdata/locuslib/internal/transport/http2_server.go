package transport

// metadata is the request-scoped header map the transport layer builds.
type metadata map[string][]string

func getMeta() metadata { return nil }

// HandleStreams dispatches frames; the body never touches the authority
// operand family — it is a pure path symbol, not a defect site.
type http2Server struct{}

func (t *http2Server) HandleStreams() {
	mdata := getMeta()
	_ = len(mdata)
	delete(mdata, "host")
	var err error
	if err != nil {
		_ = err.Error()
	}
}

// operateHeaders rejects requests missing :authority — it validates the
// guarded value but never consumes it in a faulting position: enabler.
func (t *http2Server) operateHeaders() {
	mdata := getMeta()
	if len(mdata[":authority"]) == 0 {
		return
	}
	delete(mdata, "host")
}

// legacyRoute is a declared-but-not-fix-changed symbol whose body still
// performs the faulting operation on the guarded operand family — the
// shape an incomplete fix series or a partial backport leaves behind.
func (t *http2Server) legacyRoute() {
	mdata := getMeta()
	a := mdata[":authority"]
	_ = a[0]
}
