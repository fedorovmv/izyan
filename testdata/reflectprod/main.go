package main

import (
	"reflect"
	"unsafe"

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

func unsafewrite(c *cfg, v int) {
	// Store through an unsafe.Pointer deref — can hit unexported fields.
	*(*int)(unsafe.Pointer(&c.limit)) = v
	vuln.Parse("z")
}

func callvia(c *cfg) {
	// reflect.Value.MethodByName — can invoke methods dynamically.
	reflect.ValueOf(c).MethodByName("Serve").Call(nil)
}

func main() {
	readonly(&cfg{})
}
