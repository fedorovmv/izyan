package vuln

// Runner is a pretend registry-dispatched interface for receiver-binding
// edge cases the shared dep fixture must not carry.
type Runner interface {
	Run(string) string
}

// RealRunner is the "vulnerable" impl — the product can still reach it
// through the first binding of DispatchEither.
type RealRunner struct{}

func (r *RealRunner) Run(s string) string { return s }

// SafeRunner is the impl the second binding can produce.
type SafeRunner struct{}

func (o *SafeRunner) Run(s string) string { return s }

var runners = map[string]Runner{"vulnerable": &RealRunner{}, "safe": &SafeRunner{}}

// DispatchEither binds the receiver twice — every assignment is a
// candidate binding; keeping only the last one would drop the impl the
// first lookup can still produce when repick is false.
func DispatchEither(first, second, arg string, repick bool) string {
	r := runners[first]
	if repick {
		r = runners[second]
	}
	return r.Run(arg)
}
