// getter-file stages a pre-baked artifact from the artifact depot on the
// local filesystem — a const file:// URL, operators never supply one.
package main

import (
	"log"
	"os"
	"path/filepath"

	getter "github.com/hashicorp/go-getter"
)

const depotArtifact = "file:///opt/artifact-depot/agent-v2.tar.gz"

func bootstrap(dir string) error {
	return getter.GetAny(dir, depotArtifact)
}

func main() {
	dir := filepath.Join(os.TempDir(), "agent-bootstrap")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		log.Fatal(err)
	}
	if err := bootstrap(dir); err != nil {
		log.Fatal(err)
	}
	log.Printf("agent staged at %s", dir)
}
