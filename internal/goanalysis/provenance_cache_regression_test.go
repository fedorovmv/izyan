package goanalysis

import (
	"context"
	"go/ast"
	"go/types"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"golang.org/x/tools/go/packages"
)

func TestFieldOriginDoesNotStoreAcrossExtraEviction(t *testing.T) {
	ix := fixture(t, "wireprod")
	ctx := context.Background()
	if err := ix.load(ctx); err != nil {
		t.Fatal(err)
	}
	pkgs, err := ix.loadExtra(ctx, "example.com/dep/vuln")
	if err != nil || len(pkgs) == 0 {
		t.Fatalf("load dependency: packages=%d err=%v", len(pkgs), err)
	}
	var field *types.Var
	for _, pkg := range pkgs {
		if pkg.Types == nil || pkg.PkgPath != "example.com/dep/vuln" {
			continue
		}
		conn, ok := pkg.Types.Scope().Lookup("Conn").(*types.TypeName)
		if !ok {
			continue
		}
		st, ok := conn.Type().Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			if st.Field(i).Name() == "r" {
				field = st.Field(i)
			}
		}
	}
	if field == nil {
		t.Fatal("dependency Conn.r field not found")
	}

	old := make([]*packages.Package, maxExtraPkgs)
	for i := range old {
		old[i] = &packages.Package{PkgPath: "example.com/old"}
	}
	ix.extraPkgs["old"] = old
	ix.extraOrder = append([]string{"old"}, ix.extraOrder...)
	ix.extraWeight["old"] = 0

	gen := ix.extrasGen
	origin, _, ok := ix.fieldOrigin(field, 0)
	if ix.extrasGen == gen {
		t.Fatal("field origin scan did not trigger the expected dependency reload")
	}
	if !ok || origin != domain.OriginUnknown {
		t.Fatalf("field origin after dependency scope changed = %s, %v; want UNKNOWN with a resolved field", origin, ok)
	}
}

func TestIsParamHandlesSyntheticDeclWithoutType(t *testing.T) {
	if isParam(&ast.FuncDecl{}, types.NewVar(0, nil, "value", types.Typ[types.String])) {
		t.Fatal("synthetic declaration without a type cannot bind parameters")
	}
}
