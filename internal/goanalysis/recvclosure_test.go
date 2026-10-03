package goanalysis

import (
	"context"
	"go/types"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// TestSinkClosureReceiverViaFuncValue covers the method-expression
// dispatch shape (protojson's unmarshalFunc): a method call through a
// func value supplies the receiver as arg0 (`fn(d)`). The subject
// package is loaded once by path (findSymbol) and again under the
// module pattern (caller enumeration), so the signature's parameter
// type and the receiver var's type come from different type-checker
// instances — the arg0 receiver match must not rely on types.Identical
// alone.
func TestSinkClosureReceiverViaFuncValue(t *testing.T) {
	ix := fixture(t, "recvprod")
	cl, _, err := ix.SinkClosure(context.Background(), "C-INPUT",
		"example.com/recvdep", "probe", []domain.SymbolRef{
			{Package: "example.com/recvdep/vuln", Symbol: "Decoder.Read"},
		}, -1, 16)
	if err != nil {
		t.Fatal(err)
	}
	live := 0
	receiver := false
	for _, s := range cl.Sites {
		if !s.Live {
			continue
		}
		live++
		receiver = receiver || s.Arg == -1
		if !domain.SafeOrigin(s.Origin) {
			t.Fatalf("live position %s:%d arg%d %s: %s",
				s.CallSite.File, s.CallSite.Line, s.Arg, s.Origin, s.Detail)
		}
	}
	if live == 0 {
		t.Fatal("no live sites enumerated")
	}
	if !receiver {
		t.Fatal("method-value call did not record its receiver payload position")
	}
	if !cl.Complete {
		t.Fatalf("sink closure incomplete: %+v", cl)
	}
}

// TestSameTypeAcrossTypeCheckerRuns loads the same package twice and
// checks that sameType matches the same named type across distinct
// *types.Package instances — the cross-universe case types.Identical
// cannot cover — while still distinguishing different types and
// pointer depth.
func TestSameTypeAcrossTypeCheckerRuns(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "dep"))
	if err != nil {
		t.Fatal(err)
	}
	load := func() *types.Package {
		pkgs, err := packages.Load(&packages.Config{Mode: loadMode, Dir: dir},
			"example.com/dep/vuln")
		if err != nil || len(pkgs) == 0 {
			t.Fatalf("load dep: pkgs=%d err=%v", len(pkgs), err)
		}
		return pkgs[0].Types
	}
	named := func(p *types.Package, name string) *types.Named {
		obj := p.Scope().Lookup(name)
		if obj == nil {
			t.Fatalf("%s not found", name)
		}
		n, ok := obj.Type().(*types.Named)
		if !ok {
			t.Fatalf("%s type is %T, want *types.Named", name, obj.Type())
		}
		return n
	}
	pa, pb := load(), load()
	a, b := named(pa, "Claims"), named(pb, "Claims")
	if types.Identical(a, b) {
		t.Skip("both loads share one type universe — cross-universe case untestable")
	}
	if !sameType(a, b) {
		t.Fatal("sameType must match the same named type across type-checker runs")
	}
	if !sameType(types.NewPointer(a), types.NewPointer(b)) {
		t.Fatal("sameType must match pointers across type-checker runs")
	}
	if sameType(types.NewPointer(a), b) {
		t.Fatal("sameType must not collapse pointer depth")
	}
	if sameType(a, named(pb, "URI")) {
		t.Fatal("sameType must distinguish different named types")
	}
}
