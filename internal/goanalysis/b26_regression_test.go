package goanalysis

import (
	"context"
	"go/ast"
	"go/types"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestSinkClosureKeepsSameLineCallSitesDistinct(t *testing.T) {
	ix := fixture(t, "sinklinededupprod")
	cl, _, err := ix.SinkClosure(context.Background(), "C-INPUT", "example.com/dep", "explicit test basis",
		[]domain.SymbolRef{vulnSym}, 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if len(cl.Sites) != 2 {
		t.Fatalf("payload sites=%+v, want both same-line call sites without package-selector receivers", cl.Sites)
	}
	if cl.Sites[0].CallSite.Line != cl.Sites[1].CallSite.Line ||
		cl.Sites[0].CallSite.Column == cl.Sites[1].CallSite.Column {
		t.Fatalf("call positions=%+v and %+v, want one line with distinct columns", cl.Sites[0].CallSite, cl.Sites[1].CallSite)
	}
	if cl.Sites[0].Arg != 0 || cl.Sites[1].Arg != 0 {
		t.Fatalf("payload positions=%+v, want only call argument 0", cl.Sites)
	}
	if cl.Sites[0].Origin != domain.OriginConstant || cl.Sites[1].Origin != domain.OriginExternalUntrusted {
		t.Fatalf("site origins=%s, %s; want CONSTANT and EXTERNAL_UNTRUSTED", cl.Sites[0].Origin, cl.Sites[1].Origin)
	}
	if cl.Complete {
		t.Fatal("sink closure completed despite the same-line external call")
	}
}

func TestDependencySourceWrapperDoesNotBecomeConstant(t *testing.T) {
	ix := fixture(t, "provenanceprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/provenancedep/vuln",
		Symbol:  "Parse",
	})
	if err != nil {
		t.Fatal(err)
	}
	flowByCaller := map[string]domain.DataFlow{}
	for _, site := range sites {
		if site.Function != "fileSource" && site.Function != "pureWrapper" {
			continue
		}
		flow, _, err := ix.TraceArgument(context.Background(), site, 0)
		if err != nil {
			t.Fatal(err)
		}
		flowByCaller[site.Function] = flow
	}
	if got := flowByCaller["fileSource"].Origin; got != domain.OriginUnknown {
		t.Fatalf("Load(\"literal.txt\") origin=%s, want UNKNOWN (%s)", got, flowByCaller["fileSource"].Summary)
	}
	if got := flowByCaller["pureWrapper"].Origin; got != domain.OriginConstant {
		t.Fatalf("pure wrapper origin=%s, want CONSTANT (%s)", got, flowByCaller["pureWrapper"].Summary)
	}
	assertInputNotVerified(t, ix, "example.com/provenancedep/vuln")
}

func TestFormattingCallbackIsNotClassifiedAsConstant(t *testing.T) {
	ix := fixture(t, "formatcallbackprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/provenancedep/vuln",
		Symbol:  "Parse",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range sites {
		flow, _, err := ix.TraceArgument(context.Background(), site, 0)
		if err != nil {
			t.Fatal(err)
		}
		if flow.Origin == domain.OriginConstant || flow.Origin == domain.OriginGenerated {
			t.Fatalf("fmt.Sprint(Stringer) origin=%s, want UNKNOWN or an external origin (%s)", flow.Origin, flow.Summary)
		}
		assertInputNotVerified(t, ix, "example.com/provenancedep/vuln")
		return
	}
	t.Fatal("formatting call site not found")
}

func TestReflectIndirectPreservesProvenance(t *testing.T) {
	ix := fixture(t, "reflectindirectprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/provenancedep/vuln",
		Symbol:  "Parse",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range sites {
		flow, _, err := ix.TraceArgument(context.Background(), site, 0)
		if err != nil {
			t.Fatal(err)
		}
		if flow.Origin != domain.OriginExternalUntrusted {
			t.Fatalf("reflect.Indirect origin=%s, want EXTERNAL_UNTRUSTED (%s)", flow.Origin, flow.Summary)
		}
		assertInputNotVerified(t, ix, "example.com/provenancedep/vuln")
		return
	}
	t.Fatal("reflect.Indirect call site not found")
}

func TestFieldsFuncCallbackDoesNotProduceSafeOrigin(t *testing.T) {
	ix := fixture(t, "fieldsfuncprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/provenancedep/vuln",
		Symbol:  "Parse",
	})
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%+v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin == domain.OriginConstant || flow.Origin == domain.OriginGenerated {
		t.Fatalf("FieldsFunc callback result origin=%s, want UNKNOWN or external (%s)", flow.Origin, flow.Summary)
	}
	assertInputNotVerified(t, ix, "example.com/provenancedep/vuln")
}

func TestComplexBuiltinMergesArgumentOrigins(t *testing.T) {
	ix := fixture(t, "complexprod")
	sites, err := ix.FindCallers(context.Background(), domain.SymbolRef{
		Package: "example.com/provenancedep/vuln",
		Symbol:  "Value",
	})
	if err != nil || len(sites) != 2 {
		t.Fatalf("sites=%+v err=%v", sites, err)
	}
	flows := map[string]domain.DataFlow{}
	for _, site := range sites {
		flow, _, err := ix.TraceArgument(context.Background(), site, 0)
		if err != nil {
			t.Fatal(err)
		}
		flows[site.Function] = flow
	}
	if got := flows["complexPure"].Origin; got != domain.OriginConstant {
		t.Fatalf("complex constant origin=%s, want CONSTANT (%s)", got, flows["complexPure"].Summary)
	}
	if got := flows["complexExternal"].Origin; got != domain.OriginExternalUntrusted {
		t.Fatalf("complex external origin=%s, want EXTERNAL_UNTRUSTED (%s)", got, flows["complexExternal"].Summary)
	}
	subject := domain.SymbolRef{Package: "example.com/provenancedep/vuln", Symbol: "Value"}
	cond := domain.Condition{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Subject: &subject, ArgIndex: 0}
	c := &domain.AnalysisCase{Vulnerability: domain.Vulnerability{Module: "example.com/provenancedep"}}
	claim := Verifier{Source: ix}.VerifyFalse(context.Background(), c,
		domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}, cond)
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("complex external input did not contradict FALSE: %+v", claim.NegativeVerification)
	}
}

func TestRecoverResultIsUnknownAndCannotVerifyFalse(t *testing.T) {
	ix := fixture(t, "recoverprod")
	subject := domain.SymbolRef{Package: "example.com/provenancedep/vuln", Symbol: "Value"}
	sites, err := ix.FindCallers(context.Background(), subject)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%+v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginUnknown {
		t.Fatalf("recover origin=%s, want UNKNOWN (%s)", flow.Origin, flow.Summary)
	}
	cond := domain.Condition{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Subject: &subject, ArgIndex: 0}
	c := &domain.AnalysisCase{Vulnerability: domain.Vulnerability{Module: "example.com/provenancedep"}}
	claim := Verifier{Source: ix}.VerifyFalse(context.Background(), c,
		domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}, cond)
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("recover result verified a FALSE: %+v", claim.NegativeVerification)
	}
}

func assertInputNotVerified(t *testing.T, ix *Index, module string) {
	t.Helper()
	subject := domain.SymbolRef{Package: "example.com/provenancedep/vuln", Symbol: "Parse"}
	c := &domain.AnalysisCase{Vulnerability: domain.Vulnerability{Module: module}}
	cond := domain.Condition{ID: "C-INPUT", Kind: domain.ConditionAttackerControl, Subject: &subject, ArgIndex: 0}
	claim := Verifier{Source: ix}.VerifyFalse(context.Background(), c,
		domain.Claim{ConditionID: cond.ID, Result: domain.ClaimFalse}, cond)
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status == domain.NegativeVerified {
		t.Fatalf("unsafe or unknown provenance retained VERIFIED: %+v", claim.NegativeVerification)
	}
}

func TestFunctionValueWithBodylessFactoryRemainsOpen(t *testing.T) {
	ix := fixture(t, "bodylessprod")
	ctx := context.Background()
	if err := ix.load(ctx); err != nil {
		t.Fatal(err)
	}
	pkg := ix.pkgByPath(ctx, "example.com/bodylessprod")
	if pkg == nil {
		t.Fatal("bodyless fixture package not loaded")
	}
	var enclosing *ast.FuncDecl
	var funcExpr *ast.CallExpr
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				enclosing = fn
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if _, ok := call.Fun.(*ast.CallExpr); ok {
				funcExpr = call.Fun.(*ast.CallExpr)
				return false
			}
			return true
		})
	}
	if funcExpr == nil {
		t.Fatal("bodyless factory call not found")
	}
	factory, ok := calleeObject(pkg.TypesInfo, funcExpr.Fun).(*types.Func)
	if !ok {
		t.Fatal("factory call does not resolve to a function")
	}
	decl, _ := ix.funcDecl(factory)
	if decl == nil || decl.Body != nil {
		t.Fatalf("factory declaration=%v, want a bodyless declaration", decl)
	}
	_, open := ix.funcCandidates(pkg, enclosing, funcExpr, map[ast.Expr]bool{}, 0)
	if !open {
		t.Fatal("bodyless callable-return declaration must leave candidate scope open")
	}
}

func TestSinkClosureAdvisoryMembershipDoesNotAuthorizeFallback(t *testing.T) {
	ix := fixture(t, "constprod")
	v := Verifier{Source: ix}
	subject := vulnSym
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:              "GO-TEST-1",
			Module:          "example.com/dep",
			AffectedSymbols: []domain.SymbolRef{subject},
		},
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	note := v.verifySinkClosure(context.Background(), c,
		domain.Claim{ConditionID: "C-INPUT", Result: domain.ClaimFalse}, nv, []domain.SymbolRef{subject}, 0)
	if note == "" || nv.Status != domain.NegativeInsufficientScope {
		t.Fatalf("sink-closure fallback authorized advisory membership: status=%s note=%q", nv.Status, note)
	}
	cl := c.EvidenceGraph.SinkClosureFor("C-INPUT")
	if cl == nil || cl.Basis != "" || cl.Complete {
		t.Fatalf("advisory membership created a complete closure: %+v", cl)
	}
}
