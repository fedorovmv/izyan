package exposure

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestScope(t *testing.T) {
	for addr, want := range map[string]string{
		":9090":             domain.ScopeAllInterfaces,
		"0.0.0.0:443":       domain.ScopeAllInterfaces,
		"[::]:80":           domain.ScopeAllInterfaces,
		"127.0.0.1:8080":    domain.ScopeLoopback,
		"localhost:9090":    domain.ScopeLoopback,
		"[::1]:5000":        domain.ScopeLoopback,
		"/var/run/app.sock": domain.ScopeUnix,
		"10.1.2.3:8080":     domain.ScopeHostSpecific,
		"api.internal:443":  domain.ScopeHostSpecific,
		"":                  domain.ScopeUnknown,
		"{{ .Port }}":       domain.ScopeUnknown,
	} {
		if got := Scope(addr); got != want {
			t.Errorf("Scope(%q)=%s want %s", addr, got, want)
		}
	}
}

func TestOutboundScope(t *testing.T) {
	for src, want := range map[string]string{
		"literal":      domain.ScopeStatic,
		"const":        domain.ScopeStatic,
		"env:ADDR":     domain.ScopeConfigured,
		"config:addr":  domain.ScopeConfigured,
		"var:endpoint": domain.ScopeConfigured,
		"field:c.A":    domain.ScopeConfigured,
		"":             domain.ScopeUnknown,
	} {
		if got := OutboundScope(src); got != want {
			t.Errorf("OutboundScope(%q)=%s want %s", src, got, want)
		}
	}
}

func TestScanRepoAndLookup(t *testing.T) {
	dir := t.TempDir()
	cfg := "server:\n  listen_addr: 0.0.0.0:9090\namqp:\n  url: \"amqps://broker:5671\"\nAMQP_URL=amqps://env:5671\n"
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	// vendor must be skipped
	os.MkdirAll(filepath.Join(dir, "vendor"), 0o755)
	os.WriteFile(filepath.Join(dir, "vendor", "v.yaml"), []byte("listen_addr: 1.2.3.4:5\n"), 0o644)

	items, err := ScanRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("items=%+v", items)
	}
	if got := Lookup(items, "amqp_url"); got == nil || got.Value != "amqps://env:5671" {
		t.Fatalf("Lookup(amqp_url)=%+v", got)
	}
	if got := Lookup(items, "listen_addr"); got == nil || got.Value != "0.0.0.0:9090" {
		t.Fatalf("Lookup(listen_addr)=%+v", got)
	}
	if Lookup(items, "nope") != nil {
		t.Fatal("unexpected match")
	}
}

func TestScanRepoRedactsCredentials(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "app.env"), []byte(
		"BROKER_URL=amqp://svc:secretpw@rabbit:5672/vh\nDSN=postgres://u:p@db:5432/x\nADDR=:9090\n"), 0o644)
	items, err := ScanRepo(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if strings.Contains(it.Value, "secretpw") || strings.Contains(it.Value, "u:p@") {
			t.Fatalf("credential leaked into item %s=%s", it.Key, it.Value)
		}
	}
	var found bool
	for _, it := range items {
		if strings.Contains(it.Value, "***@rabbit:5672") || strings.Contains(it.Value, "***@db:5432") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected redacted URL values, got %+v", items)
	}
}
