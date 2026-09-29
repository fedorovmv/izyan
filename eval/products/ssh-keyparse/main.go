// ssh-keyparse is a fleet-maintenance tool that audits the local
// authorized_keys file: it parses every entry, deduplicates keys by
// fingerprint and prints the allow-list it would install. It never opens
// an SSH connection — the ssh package is used as a key-format library.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func fingerprints(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	rest := data
	for len(rest) > 0 {
		key, _, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return nil, fmt.Errorf("malformed entry: %w", err)
		}
		seen[ssh.FingerprintSHA256(key)] = true
		rest = next
	}
	return seen, nil
}

func main() {
	path := flag.String("keys", "authorized_keys", "authorized_keys file to audit")
	flag.Parse()
	fps, err := fingerprints(*path)
	if err != nil {
		log.Fatal(err)
	}
	var out []string
	for fp := range fps {
		out = append(out, fp)
	}
	fmt.Printf("%d distinct key(s):\n%s\n", len(out), strings.Join(out, "\n"))
}
