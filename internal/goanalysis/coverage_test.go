package goanalysis

import (
	"context"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

var uriStringSym = domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "URI.String"}

func TestGatedRefsFindsTagExcludedCall(t *testing.T) {
	ix := fixture(t, "gatedprod")
	sites, err := ix.GatedRefs(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("sites=%+v", sites)
	}
	if !strings.HasSuffix(sites[0].File, "special.go") || sites[0].Function != "gatedCall" {
		t.Fatalf("site=%+v", sites[0])
	}
	// The typed index does not see the gated file.
	direct, err := ix.SearchSymbol(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 0 {
		t.Fatalf("typed search unexpectedly sees gated ref: %+v", direct)
	}
}

func TestGatedRefsNoneWithoutGatedFiles(t *testing.T) {
	ix := fixture(t, "leakprod")
	sites, err := ix.GatedRefs(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 0 {
		t.Fatalf("sites=%+v", sites)
	}
}

func TestInterfaceDispatchSites(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	sites, err := ix.InterfaceDispatchSites(context.Background(), uriStringSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("sites=%+v", sites)
	}
	if sites[0].Function != "render" {
		t.Fatalf("enclosing=%q", sites[0].Function)
	}
	// The typed search sees the interface, not the concrete impl.
	direct, err := ix.SearchSymbol(context.Background(), uriStringSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(direct) != 0 {
		t.Fatalf("typed search unexpectedly sees dispatched call: %+v", direct)
	}
}

func TestInterfaceDispatchSitesPlainFunc(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	sites, err := ix.InterfaceDispatchSites(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 0 {
		t.Fatalf("plain function subject must not report dispatch sites: %+v", sites)
	}
}

// VerifyFalse downgrades a would-be VERIFIED negative when a reference
// exists only in a build-tag-excluded file.
func TestVerifyFalseGatedFileDowngrades(t *testing.T) {
	ix := fixture(t, "gatedprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{vulnSym},
	}
	claim := domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}
	out := v.VerifyFalse(context.Background(), c, claim, cond)
	nv := out.NegativeVerification
	if nv == nil || nv.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v", nv)
	}
	if !strings.Contains(nv.Notes, "build tags") {
		t.Fatalf("notes=%q", nv.Notes)
	}
}

// VerifyFalse downgrades on interface-dispatch candidates the typed
// search cannot attribute to the concrete method.
func TestVerifyFalseInterfaceDispatchDowngrades(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	cond := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{uriStringSym},
	}
	claim := domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}
	out := v.VerifyFalse(context.Background(), c, claim, cond)
	nv := out.NegativeVerification
	if nv == nil || nv.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v", nv)
	}
	if !strings.Contains(nv.Notes, "interface-dispatched") {
		t.Fatalf("notes=%q", nv.Notes)
	}
}

// A FALSE reachability claim cannot be verified by "no product references"
// when the subject lives in an internal package or is unexported: the
// product could never name it, so the observation is vacuous and dep-internal
// dispatch (registries, callbacks) stays un-closed scope.
func TestVerifyReachableFalseInternalSubjectNotVerified(t *testing.T) {
	v := Verifier{}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-REACH", Result: domain.ClaimFalse}
	subjects := []domain.SymbolRef{
		{Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac", Symbol: "builder.ParseFilterConfig"},
		{Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac", Symbol: "parseConfig"},
	}
	out := v.verifyReachableFalse(claim, nv, subjects, map[string][]domain.CallSite{})
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v", got)
	}
	if !strings.Contains(got.Notes, "visibility") {
		t.Fatalf("notes=%q", got.Notes)
	}
}

func TestProductReferenceable(t *testing.T) {
	cases := []struct {
		ref  domain.SymbolRef
		want bool
	}{
		{domain.SymbolRef{Package: "golang.org/x/crypto/ssh", Symbol: "NewServerConn"}, true},
		{domain.SymbolRef{Package: "github.com/miekg/dns", Symbol: "ParseZone"}, true},
		{domain.SymbolRef{Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac", Symbol: "builder.ParseFilterConfig"}, false},
		{domain.SymbolRef{Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac", Symbol: "ParseFilterConfig"}, false},
		{domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "builder.run"}, false},
		{domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "URI.String"}, true},
	}
	for _, tc := range cases {
		if got := productReferenceable(tc.ref); got != tc.want {
			t.Fatalf("productReferenceable(%+v)=%v want %v", tc.ref, got, tc.want)
		}
	}
}
