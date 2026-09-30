package goanalysis

import (
	"context"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"golang.org/x/tools/go/packages"
)

func TestIngressTypeOfDoesNotInvokeFormattingCallbacks(t *testing.T) {
	arg := ast.NewIdent("value")
	call := &ast.CallExpr{Args: []ast.Expr{arg}}
	pkg := &packages.Package{TypesInfo: &types.Info{Types: map[ast.Expr]types.TypeAndValue{
		arg: {Type: types.NewInterfaceType(nil, nil).Complete()},
	}}}
	fn := types.NewFunc(token.NoPos, types.NewPackage("reflect", "reflect"), "TypeOf", nil)
	s := &ingressScan{}
	s.scanStdlibCall(pkg, fnDeclRef{}, call, fn, nil)
	if len(s.items) != 0 || len(s.blockers) != 0 {
		t.Fatalf("reflect.TypeOf added autonomous sources: items=%+v blockers=%v", s.items, s.blockers)
	}
}

func TestIngressInventoryTracksIndependentSources(t *testing.T) {
	tests := []struct {
		name    string
		product string
		pkg     string
		callee  string
		origin  domain.DataOrigin
		detail  string
	}{
		{"function reassignment", "ingressfuncprod", "example.com/ingressdep/funcvalue", "os.Args", domain.OriginExternalUntrusted, ""},
		{"LookupEnv", "ingresslookupprod", "example.com/ingressdep/lookup", "os.LookupEnv", domain.OriginUnknown, ""},
		{"second init declaration", "ingressinitprod", "example.com/ingressdep/multiinit", "os.Args", domain.OriginExternalUntrusted, ""},
		{"package initializer", "ingressinitializerprod", "example.com/ingressdep/initializer", "os.Args", domain.OriginExternalUntrusted, ""},
		{"formatting callback", "ingressformatprod", "example.com/ingressdep/format", "fmt.Sprint", domain.OriginUnknown, "formatting method"},
		{"recover value", "ingressrecoverprod", "example.com/ingressdep/recover", "builtin.recover", domain.OriginUnknown, "panic value"},
		{"void callback", "ingresslogprod", "example.com/ingressdep/logvoid", "log.Print", domain.OriginUnknown, "formatting method"},
		{"unmodeled void call", "ingresslogprod", "example.com/ingressdep/logvoid", "log.Println", domain.OriginUnknown, "independent effects"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ix := fixture(t, tt.product)
			subject := domain.SymbolRef{Package: tt.pkg, Symbol: "Sink"}
			cl, _, err := ix.IngressInventory(context.Background(), "example.com/ingressdep", []domain.SymbolRef{subject}, 16)
			if err != nil {
				t.Fatal(err)
			}
			if !ingressHasItem(cl, tt.callee, tt.origin, tt.detail) {
				t.Fatalf("inventory has no %s item: %+v; blockers=%v", tt.callee, cl.Items, cl.Blockers)
			}
			assertIngressNotVerified(t, ix, subject)
		})
	}
}

func TestIngressInventoryKeepsPureMinimalClosureComplete(t *testing.T) {
	ix := fixture(t, "constprod")
	cl, _, err := ix.IngressInventory(context.Background(), "example.com/dep", []domain.SymbolRef{vulnSym}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if !cl.Complete {
		t.Fatalf("pure minimal ingress closure incomplete: items=%+v blockers=%v", cl.Items, cl.Blockers)
	}
	for _, it := range cl.Items {
		if it.Origin != domain.OriginConstant && it.Origin != domain.OriginGenerated {
			t.Fatalf("pure minimal closure has non-safe ingress item: %+v", it)
		}
	}
}

func TestIngressInventoryBlocksBodylessConeFunction(t *testing.T) {
	ix := fixture(t, "bodylessprod")
	cl, _, err := ix.IngressInventory(context.Background(), "example.com/bodylessdep", []domain.SymbolRef{
		{Package: "example.com/bodylessdep/vuln", Symbol: "Native"},
	}, 16)
	if err != nil {
		t.Fatal(err)
	}
	if cl.Complete || !ingressHasBlocker(cl, "body unavailable") {
		t.Fatalf("bodyless cone function was not left open: items=%+v blockers=%v", cl.Items, cl.Blockers)
	}
}

func assertIngressNotVerified(t *testing.T, ix *Index, subject domain.SymbolRef) {
	t.Helper()
	c := &domain.AnalysisCase{Vulnerability: domain.Vulnerability{Module: "example.com/ingressdep"}}
	cond := domain.Condition{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Subject: &subject, ArgIndex: 0}
	claim := (Verifier{Source: ix}).VerifyFalse(context.Background(), c,
		domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}, cond)
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status == domain.NegativeVerified {
		t.Fatalf("unsafe ingress probe retained VERIFIED: %+v", claim.NegativeVerification)
	}
}

func ingressHasItem(cl domain.IngressClosure, callee string, origin domain.DataOrigin, detail string) bool {
	for _, it := range cl.Items {
		if it.Callee == callee && it.Origin == origin && (detail == "" || strings.Contains(it.Detail, detail)) {
			return true
		}
	}
	return false
}

func ingressHasBlocker(cl domain.IngressClosure, needle string) bool {
	for _, blocker := range cl.Blockers {
		if strings.Contains(blocker, needle) {
			return true
		}
	}
	return false
}
