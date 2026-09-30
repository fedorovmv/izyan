package goanalysis

import (
	"bytes"
	"context"
	"fmt"
	"go/ast"
	"go/printer"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"example.com/vuln-analyzer/internal/domain"
)

// SymbolFaultingUse reports whether the function body of ref uses any of
// the given operand expressions in a faulting position: indexing the value
// (x[i]), selecting through it (x.f), or calling it (x(...)). Exploit-model
// locus derivation uses this to separate a defect site — the fix guards a
// value the same function then consumes unsafely — from an upstream enabler
// whose guard only rejects the bad input without the function itself
// performing the vulnerable operation.
//
// The scan is syntactic: operands come from guard expressions added by the
// fix diff, and a match means the guarded value flows into a position that
// faults when the guarded property does not hold. Unresolvable symbols or
// unparseable operands return an error — callers must not treat that as a
// negative finding.
func (ix *Index) SymbolFaultingUse(ctx context.Context, ref domain.SymbolRef, operands []string) (bool, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return false, err
	}
	typeName, meth := splitSymbol(ref.Symbol)
	fn := ix.findFuncDecl(ctx, ref.Package, typeName, meth)
	if fn == nil {
		return false, fmt.Errorf("function %s.%s not found in loaded source", ref.Package, ref.Symbol)
	}
	set := ix.operandSet(ctx, fn, operands)
	if len(set) == 0 {
		return false, nil
	}
	base := func(e ast.Expr) string {
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, ix.fset, e); err != nil {
			return ""
		}
		return normalizeExpr(buf.String())
	}
	fault := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if fault {
			return false
		}
		switch e := n.(type) {
		case *ast.IndexExpr:
			fault = fault || set[base(e.X)]
		case *ast.SelectorExpr:
			fault = fault || set[base(e.X)]
		case *ast.CallExpr:
			fault = fault || set[base(e.Fun)]
		}
		return !fault
	})
	return fault, nil
}

// OperandFamily expands guard operands through the guarding function's own
// alias bindings: `authority := md.Get(":authority")` inside that body makes
// the family {authority, md.Get(":authority")}. Locus derivation scans
// declared-but-not-fix-changed symbols against the union family of all
// guards in the patch, so a defect site spelling the guarded value
// differently is not silently classified as a path symbol.
func (ix *Index) OperandFamily(ctx context.Context, ref domain.SymbolRef, operands []string) ([]string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	typeName, meth := splitSymbol(ref.Symbol)
	fn := ix.findFuncDecl(ctx, ref.Package, typeName, meth)
	if fn == nil {
		return nil, fmt.Errorf("function %s.%s not found in loaded source", ref.Package, ref.Symbol)
	}
	set := ix.operandSet(ctx, fn, operands)
	var out []string
	for op := range set {
		out = append(out, op)
	}
	sort.Strings(out)
	return out, nil
}

// operandSet renders operand expressions and closes over the function's
// alias bindings: `a := mdata[k]` makes `a[i]` the same faulting index as
// `mdata[k][i]`. The fixpoint sweep must not miss a real binding — a missed
// fault would wrongly classify a defect site as an enabler or a path symbol
// and shrink the falsifier's coverage obligation.
func (ix *Index) operandSet(_ context.Context, fn *ast.FuncDecl, operands []string) map[string]bool {
	base := func(e ast.Expr) string {
		var buf bytes.Buffer
		if err := printer.Fprint(&buf, ix.fset, e); err != nil {
			return ""
		}
		return normalizeExpr(buf.String())
	}
	set := map[string]bool{}
	for _, op := range operands {
		if op = normalizeExpr(op); op != "" {
			set[op] = true
		}
	}
	for grew := true; grew; {
		grew = false
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, rhs := range as.Rhs {
				if !set[base(rhs)] || i >= len(as.Lhs) {
					continue
				}
				if id, ok := as.Lhs[i].(*ast.Ident); ok && !set[id.Name] {
					set[id.Name] = true
					grew = true
				}
			}
			return true
		})
	}
	return set
}

func normalizeExpr(s string) string {
	return strings.Join(strings.Fields(s), "")
}

// findFuncDecl locates the FuncDecl for (typeName, meth) in the package —
// product packages first, then a targeted extra load like findSymbol.
func (ix *Index) findFuncDecl(ctx context.Context, pkgPath, typeName, meth string) *ast.FuncDecl {
	if fn := findFuncInPkgs(ix.pkgs, pkgPath, typeName, meth); fn != nil {
		return fn
	}
	extra, err := ix.loadExtra(ctx, pkgPath)
	if err != nil {
		return nil
	}
	return findFuncInPkgs(extra, pkgPath, typeName, meth)
}

func findFuncInPkgs(pkgs []*packages.Package, pkgPath, typeName, meth string) *ast.FuncDecl {
	for _, pkg := range pkgs {
		if pkg.PkgPath != pkgPath {
			continue
		}
		for _, f := range pkg.Syntax {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != meth {
					continue
				}
				if typeName == "" && fn.Recv == nil {
					return fn
				}
				if typeName != "" && fn.Recv != nil &&
					recvASTType(fn.Recv.List[0].Type) == typeName {
					return fn
				}
			}
		}
	}
	return nil
}

// recvASTType extracts the receiver's base type name from an AST type,
// unwrapping pointer and generic instantiation: `*http2Server` ->
// "http2Server". (recvTypeName on types.Type already exists in source.go.)
func recvASTType(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return recvASTType(t.X)
	case *ast.IndexExpr:
		return recvASTType(t.X)
	case *ast.IndexListExpr:
		return recvASTType(t.X)
	}
	return ""
}
