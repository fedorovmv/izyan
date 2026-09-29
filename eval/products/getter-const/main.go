// getter-const is the release bootstrapper: it always downloads the same
// pinned internal release artifact into the deployment directory.
// The URL is a build-time constant — operators never supply one.
package main

import (
	"log"
	"os"
	"path/filepath"

	getter "github.com/hashicorp/go-getter"
)

// releaseArtifact is pinned at build; upgrading means shipping a new
// bootstrapper, never editing the URL at runtime.
const releaseArtifact = "https://releases.internal.example.com/agent/v2/agent.tar.gz"

func bootstrap(dir string) error {
	if err := getter.GetAny(dir, releaseArtifact); err != nil {
		return err
	}
	return nil
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
