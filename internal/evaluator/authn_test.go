package evaluator

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func authnCond() domain.Condition {
	return domain.Condition{
		ID:   "C-AUTH",
		Kind: domain.ConditionAuthn,
	}
}

func TestAuthenticationWired(t *testing.T) {
	c := exposureCase(
		domain.ExposureFact{Direction: "inbound", Kind: "listener", Target: "net.Listen",
			Address: ":9090", AddressSource: "literal", Scope: domain.ScopeAllInterfaces},
		domain.ExposureFact{Direction: "inbound", Kind: "auth-middleware", Target: "authMw",
			CallSite: domain.CallSite{File: "srv.go", Line: 12}},
	)
	cl := Authentication{}.Evaluate(authnCond(), c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("result=%s (%s)", cl.Result, cl.Explanation)
	}
	if !strings.Contains(cl.Explanation, "authMw") {
		t.Fatalf("explanation=%s", cl.Explanation)
	}
	found := false
	for _, l := range cl.Limitations {
		if strings.Contains(l, "per-route") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected per-route caveat, got %v", cl.Limitations)
	}
}

func TestAuthenticationNoWiring(t *testing.T) {
	// Listener present but no auth middleware: absence is not proof —
	// the claim must stay UNKNOWN, never FALSE.
	c := exposureCase(domain.ExposureFact{Direction: "inbound", Kind: "listener",
		Target: "net.Listen", Address: ":9090", AddressSource: "literal",
		Scope: domain.ScopeAllInterfaces})
	cl := Authentication{}.Evaluate(authnCond(), c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s, want UNKNOWN", cl.Result)
	}
}

func TestAuthenticationMiddlewareNoListener(t *testing.T) {
	// Auth wiring without a resolved listener may be dead code — UNKNOWN.
	c := exposureCase(domain.ExposureFact{Direction: "inbound", Kind: "auth-middleware",
		Target: "authMw", CallSite: domain.CallSite{File: "srv.go", Line: 12}})
	cl := Authentication{}.Evaluate(authnCond(), c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s, want UNKNOWN", cl.Result)
	}
	if !strings.Contains(cl.Limitations[0], "no inbound listener") {
		t.Fatalf("lims=%v", cl.Limitations)
	}
}
