// http2-server is the product's public API edge: an HTTPS server that by
// default negotiates HTTP/2 and dispatches REST routes.
package main

import (
	"fmt"
	"log"
	"net/http"
)

func api(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `{"ok":true,"proto":%q}`, r.Proto)
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", api)
	srv := &http.Server{Addr: ":8443", Handler: mux}
	log.Fatal(srv.ListenAndServeTLS("server.crt", "server.key"))
}
