package goanalysis

import (
	"context"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func findExposure(facts []domain.ExposureFact, target, addr, source string) *domain.ExposureFact {
	for i := range facts {
		f := &facts[i]
		if f.Target == target && f.Address == addr && (source == "" || f.AddressSource == source) {
			return f
		}
	}
	return nil
}

func TestListenSites(t *testing.T) {
	ix := fixture(t, "listenprod")
	facts, err := ix.ListenSites(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []struct{ target, addr, source string }{
		{"net.Listen", ":9090", "literal"},
		{"net.Listen", ":9091", "const"},
		{"net.Listen", "127.0.0.1:8081", "literal"}, // local var initializer resolved
		{"net.Listen", "", "env:BIND_ADDR"},
		{"net/http.Server.ListenAndServe", ":8443", "literal"},
	} {
		f := findExposure(facts, want.target, want.addr, want.source)
		if f == nil {
			t.Fatalf("no fact for %s=%s src=%s; got %+v", want.target, want.addr, want.source, facts)
		}
	}
}

func TestDialSites(t *testing.T) {
	ix := fixture(t, "listenprod")
	facts, err := ix.DialSites(context.Background(), "example.com/dep")
	if err != nil {
		t.Fatal(err)
	}
	f := findExposure(facts, "example.com/dep/vuln.Dial", "amqps://broker.internal:5671", "literal")
	if f == nil {
		t.Fatalf("no dial fact; got %+v", facts)
	}
	if f.Direction != "outbound" || f.AddressSource != "literal" {
		t.Fatalf("dial fact=%+v", f)
	}
	// A different module yields nothing.
	facts, err = ix.DialSites(context.Background(), "example.com/other")
	if err != nil || len(facts) != 0 {
		t.Fatalf("other module: facts=%+v err=%v", facts, err)
	}
}

func TestListenSites_ConfigFieldAndPackageVar(t *testing.T) {
	ix := fixture(t, "listenprod")
	facts, err := ix.ListenSites(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	// 1. Package-level var cfgAddr = "127.0.0.1:8080"
	fPkgVar := findExposure(facts, "net.Listen", "127.0.0.1:8080", "var:cfgAddr")
	if fPkgVar == nil {
		t.Fatalf("expected package var fact with address 127.0.0.1:8080; got %+v", facts)
	}
	if fPkgVar.Scope != domain.ScopeLoopback {
		t.Fatalf("expected ScopeLoopback, got %s", fPkgVar.Scope)
	}

	// 2. Struct field serverCfg.Addr = "127.0.0.1:8888"
	fField := findExposure(facts, "net.Listen", "127.0.0.1:8888", "field:ServerConfig.Addr")
	if fField == nil {
		t.Fatalf("expected struct field fact with address 127.0.0.1:8888; got %+v", facts)
	}
	if fField.Scope != domain.ScopeLoopback {
		t.Fatalf("expected ScopeLoopback, got %s", fField.Scope)
	}
}

