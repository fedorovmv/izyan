package vuln

// Runner is a pretend registry-dispatched interface — the go-getter
// getters[scheme] shape: callers name the interface method, the concrete
// impl is picked by a map key at runtime.
type Runner interface {
	Run(string) string
}

// RealRunner is registered in the dispatch table and therefore a live
// dispatch target.
type RealRunner struct{}

func (r *RealRunner) Run(s string) string { return s }

// NeverRunner implements Runner but is never instantiated in non-test
// code: it cannot be the dynamic type behind a Runner value.
type NeverRunner struct{}

func (n *NeverRunner) Run(s string) string { return s }

// OtherRunner is instantiated via the registry but registered under a
// key the product never passes — dispatch-key narrowing must exclude it
// while instantiation narrowing keeps it.
type OtherRunner struct{}

func (o *OtherRunner) Run(s string) string { return s }

var runners = map[string]Runner{"real": &RealRunner{}, "other": &OtherRunner{}}

// Dispatch resolves name through the registry — static edges reach the
// interface method; instantiation narrowing must keep only RealRunner
// as a dispatch target.
func Dispatch(name, arg string) string {
	r, ok := runners[name]
	if !ok {
		return arg
	}
	return r.Run(arg)
}
