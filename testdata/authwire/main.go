package main

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

func authMw(h http.Handler) http.Handler { return h }
func sessionCheck(h http.Handler) http.Handler { return h }
func plain(h http.Handler) http.Handler { return h }

// Server wiring sits behind two auth-marked middlewares and one
// unrelated wrapper — only the auth-named ones must be reported.
func main() {
	r := chi.NewRouter()
	r.Use(authMw)
	r.With(sessionCheck).Get("/x", func(w http.ResponseWriter, req *http.Request) {})
	r.Use(plain)
	fmt.Println(http.ListenAndServe(":8080", r))
}

func wrapped() {
	fmt.Println(http.ListenAndServeTLS(":8443", "", "", authMw(http.DefaultServeMux)))
}
