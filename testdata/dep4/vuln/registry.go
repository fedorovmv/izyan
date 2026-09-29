package vuln

// Runner is a pretend registry-dispatched interface for alias-mutation
// edge cases.
type Runner interface {
	Run(string) string
}

type RealRunner struct{}

func (r *RealRunner) Run(s string) string { return s }

type SafeRunner struct{}

func (o *SafeRunner) Run(s string) string { return s }

// ExtraRunner is never referenced by the literal table — it is
// instantiated product-side; whether it is a dispatch target is decided
// by the completeness of the `runners` table.
type ExtraRunner struct{}

func (e *ExtraRunner) Run(s string) string { return s }

var runners = map[string]Runner{"vulnerable": &RealRunner{}, "safe": &SafeRunner{}}

// DispatchAlias aliases the registry then writes through the alias —
// `a[...] = ` never names `runners`, so completeness tracking that only
// watches the declared variable would wrongly keep the narrowed table
// and drop runtime-registered impls.
func DispatchAlias(arg string) string {
	a := runners
	a["runtime"] = &RealRunner{}
	r, ok := runners[arg]
	if !ok {
		return arg
	}
	return r.Run(arg)
}
