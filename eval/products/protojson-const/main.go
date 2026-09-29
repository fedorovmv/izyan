// protojson-const decodes the embedded bootstrap document — the JSON
// bytes are a build-time constant, never read from the wire.
package main

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const bootstrap = `{"name":"baseline","flags":{"region":"us-east"}}`

func load() *structpb.Struct {
	msg, err := structpb.NewStruct(map[string]any{})
	if err != nil {
		panic(err)
	}
	if err := protojson.Unmarshal([]byte(bootstrap), msg); err != nil {
		panic(err)
	}
	return msg
}

func main() {
	fmt.Println(load().AsMap()["name"])
}
