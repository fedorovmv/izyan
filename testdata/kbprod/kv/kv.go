package kv

var updates = make(chan string, 1)

var store = map[string]string{"seed": <-updates}

// Get reads a value from the package store — a stand-in for a custom
// config/kv lookup the analyzer does not recognize out of the box.
func Get(key string) string { return store[key] }
