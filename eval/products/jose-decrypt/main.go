// jose-decrypt is the token-intake edge of a job queue: workers POST
// compact-serialized JOSE tokens to /intake, the service verifies or
// decrypts them with the shared key and forwards the payload.
package main

import (
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	jose "github.com/dvsekhvalnov/jose2go"
)

var sharedKey = []byte(os.Getenv("JOSE_SHARED_KEY"))

func intake(token string) (string, error) {
	payload, _, err := jose.Decode(token, sharedKey)
	if err != nil {
		return "", err
	}
	return payload, nil
}

func handleIntake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	payload, err := intake(strings.TrimSpace(string(body)))
	if err != nil {
		http.Error(w, "token rejected", http.StatusUnauthorized)
		return
	}
	_, _ = io.WriteString(w, payload)
}

func main() {
	if len(sharedKey) == 0 {
		sharedKey = []byte("development-only-key")
	}
	http.HandleFunc("/intake", handleIntake)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
