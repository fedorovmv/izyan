package server

func mdGet(key string) []string { return nil }

// RouteAndProcess indexes the authority slice — the defect site; the fix
// adds `if len(authority) == 0` right before the index expression.
func RouteAndProcess() string {
	authority := mdGet(":authority")
	return authority[0]
}
