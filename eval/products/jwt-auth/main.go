// jwt-auth is an internal API gateway: every request must carry a Bearer
// JWT in the Authorization header; claims are validated by jwt-go and the
// subject is forwarded to the backend handler.
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

var hmacKey = []byte("gateway-shared-secret")

func parseToken(header string) (jwt.MapClaims, error) {
	raw := strings.TrimSpace(strings.TrimPrefix(header, "Bearer "))
	if raw == "" {
		return nil, fmt.Errorf("no bearer token")
	}
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(raw, claims, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected alg %v", t.Header["alg"])
		}
		return hmacKey, nil
	})
	if err != nil {
		return nil, err
	}
	return claims, nil
}

func withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims, err := parseToken(r.Header.Get("Authorization"))
		if err != nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sub, _ := claims["sub"].(string)
		next(w, r.WithContext(context.WithValue(r.Context(), "sub", sub)))
	}
}

func profile(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "subject=%s", r.Context().Value("sub"))
}

func main() {
	http.HandleFunc("/me", withAuth(profile))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
