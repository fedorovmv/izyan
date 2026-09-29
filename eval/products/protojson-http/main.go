// protojson-http accepts protobuf JSON payloads POSTed to /records and
// decodes them with protojson.Unmarshal.
package main

import (
	"io"
	"log"
	"net/http"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func ingest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	msg := &emptypb.Empty{}
	if err := protojson.Unmarshal(body, msg); err != nil {
		http.Error(w, "invalid json: "+err.Error(), http.StatusBadRequest)
		return
	}
	_ = dynamicpb.NewMessage(nil)
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	http.HandleFunc("/records", ingest)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
