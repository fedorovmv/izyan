// getter-fetch is an artifact staging service: automation POSTs a source
// URL to /fetch, the service downloads it into the staging area and
// reports the local path.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"

	getter "github.com/hashicorp/go-getter"
)

type fetchRequest struct {
	URL string `json:"url"`
}

func stage(url string) (string, error) {
	dst, err := os.MkdirTemp("", "stage-*")
	if err != nil {
		return "", err
	}
	if err := getter.GetAny(dst, url); err != nil {
		return "", fmt.Errorf("fetch %s: %w", url, err)
	}
	return filepath.Clean(dst), nil
}

func handleFetch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req fetchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		http.Error(w, "url required", http.StatusBadRequest)
		return
	}
	dst, err := stage(req.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"staged": dst})
}

func main() {
	http.HandleFunc("/fetch", handleFetch)
	log.Fatal(http.ListenAndServe(":8080", nil))
}
