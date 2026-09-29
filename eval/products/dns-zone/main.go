// dns-zone is a zone-management service for a small authoritative DNS
// setup: operators POST a zone file to /zone/import, the service parses
// the records, reports the accepted set and hands them to the signer.
package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

func importZone(origin, text string) (int, error) {
	count := 0
	for tok := range dns.ParseZone(strings.NewReader(text), origin, "upload.zone") {
		if tok.Error != nil {
			return count, fmt.Errorf("record %d: %w", count, tok.Error)
		}
		count++
	}
	return count, nil
}

func handleImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	origin := r.URL.Query().Get("origin")
	if origin == "" {
		origin = "example.com."
	}
	n, err := importZone(origin, string(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "imported %d record(s)\n", n)
}

func main() {
	http.HandleFunc("/zone/import", handleImport)
	log.Fatal(http.ListenAndServe(":8053", nil))
}
