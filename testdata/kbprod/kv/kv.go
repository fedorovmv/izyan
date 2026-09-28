package kv

var store = map[string]string{}

// Get reads a value from the package store — a stand-in for a custom
// config/kv lookup the analyzer does not recognize out of the box.
func Get(key string) string { return store[key] }
