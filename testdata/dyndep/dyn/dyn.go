package dyn

// RunWith invokes the supplied function — a func-value call the static
// call graph cannot resolve: the edge set is incomplete, not empty.
func RunWith(f func(string) string, s string) string { return f(s) }

// AnonRunner dispatches through an anonymous interface type — no named
// interface means no enumerable impl edges either.
func AnonRunner(r interface{ Run() string }) string { return r.Run() }

// Vulnerable is the pretend affected symbol — reachable shape only if
// some caller wires it; on an opaque graph reachability stays unknown.
func Vulnerable(s string) string { return s }
