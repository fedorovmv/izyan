package vuln

// Runner is a pretend registry-dispatched interface for map-mutation
// edge cases.
type Runner interface {
	Run(string) string
}

type RealRunner struct{}

func (r *RealRunner) Run(s string) string { return s }

type SafeRunner struct{}

func (o *SafeRunner) Run(s string) string { return s }

// lateRunners is index-mutated through Register — its literal content is
// not the complete table, so dispatch narrowing must not restrict it:
// impls registered at runtime stay reachable.
var lateRunners = map[string]Runner{}

func Register(name string, r Runner) { lateRunners[name] = r }

// DispatchLate resolves through a registry whose entries are added at
// runtime — the impl set is unknowable, never narrow.
func DispatchLate(name, arg string) string {
	r, ok := lateRunners[name]
	if !ok {
		return arg
	}
	return r.Run(arg)
}
