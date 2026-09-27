package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSourceModuleCache(t *testing.T) {
	// A real module-cache file: golang.org/x/tools is a module dep of the
	// analyzer itself; emulate by planting a file under a fake modcache.
	mc := t.TempDir()
	target := filepath.Join(mc, "example.com", "dep@v1.0.0", "vuln.go")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("package vuln\n\nfunc Parse(s string) string { return s }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ix := &Index{Dir: "../../testdata/guardprod", Env: []string{"GOMODCACHE=" + mc}}
	src, err := ix.ReadSource(context.Background(), target, 0, 0)
	if err != nil {
		t.Fatalf("read_source in module cache: %v", err)
	}
	if !strings.Contains(src, "func Parse") {
		t.Fatalf("unexpected content: %s", src)
	}
	// Outside both scopes still refused.
	if _, err := ix.ReadSource(context.Background(), "/etc/passwd", 0, 0); err == nil {
		t.Fatal("read_source escaped confinement")
	}
}
