package main

import (
	"reflect"

	"example.com/dep/vuln"
)

type cfg struct {
	// unexported — reflect.Value.Set* cannot write it.
	limit int
	// Exported — reachable to reflect.Value.Set*.
	Mode int
}

func readonly(c *cfg) {
	// A bare reflect import + read-only calls do not write fields.
	_ = reflect.TypeOf(c.limit).Kind()
	vuln.Parse("x")
}

func writevia(c *cfg, v int) {
	// reflect.Value.Set* on an exported field — an invisible write.
	reflect.ValueOf(c).Elem().FieldByName("Mode").SetInt(int64(v))
	vuln.Parse("y")
}

func main() {
	readonly(&cfg{})
}
