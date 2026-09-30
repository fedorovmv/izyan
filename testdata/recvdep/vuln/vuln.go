package vuln

// Decoder is the subject receiver type: methods read receiver state.
type Decoder struct{ buf []byte }

// NewDecoder builds a decoder over b.
func NewDecoder(b []byte) Decoder { return Decoder{buf: b} }

// Read is the pretend advisory sink — it consumes receiver state, so a
// sink-closure position classifies `d` inside its callers' bodies.
func (d Decoder) Read() byte { return d.buf[0] }

// Unmarshal invokes the sink inside a method body; in this fixture the
// method is only ever invoked through func values — `fn(d)` calls where
// the receiver travels as arg0 (the protojson unmarshalFunc shape).
func (d Decoder) Unmarshal() byte {
	return d.Read()
}
