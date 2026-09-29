// Package deep holds the vulnerable subject — its caller lives in a
// sibling package of the same module, so a package-scoped caller scan
// would miss it.
package deep

// Sink is the pretend vulnerable entry — exported, advisory-listed.
func Sink(s string) string { return s }
