package vuln

// Runner is a pretend registry-dispatched interface for cross-module
// mutation edge cases.
type Runner interface {
	Run(string) string
}

type RealRunner struct{}

func (r *RealRunner) Run(s string) string { return s }

type SafeRunner struct{}

func (o *SafeRunner) Run(s string) string { return s }

// ExtraRunner is instantiated product-side only — a dispatch target
// exactly when the exported registry is not narrowed to its literal.
type ExtraRunner struct{}

func (e *ExtraRunner) Run(s string) string { return s }

// Registry is exported: any importing package can add entries, so its
// literal is never the complete table unless no mutation site exists
// anywhere — including product code.
var Registry = map[string]Runner{"vulnerable": &RealRunner{}, "safe": &SafeRunner{}}

// DispatchExported resolves through the exported registry.
func DispatchExported(arg string) string {
	r, ok := Registry[arg]
	if !ok {
		return arg
	}
	return r.Run(arg)
}
