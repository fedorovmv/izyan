package goanalysis

import (
	"context"
	"go/ast"
	"go/types"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
	"golang.org/x/tools/go/packages"
)

// FieldAssignments finds product-code assignments to a "Type.Field"
// subject: composite-literal keys (`Type{Field: v}`) and selector
// assignments (`x.Field = v`). The assigned value is resolved to a
// literal or const value when statically determinable.
func (ix *Index) FieldAssignments(ctx context.Context, ref domain.SymbolRef) ([]domain.ConfigAssignment, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	key := ref.Package + "." + ref.Symbol
	var out []domain.ConfigAssignment
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			var enc *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enc = fn
				}
				switch e := n.(type) {
				case *ast.CompositeLit:
					_, fname := splitSymbol(ref.Symbol)
					for _, elt := range e.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						id, ok := kv.Key.(*ast.Ident)
						if !ok || id.Name != fname || !litFieldMatch(info, e, ref) {
							continue
						}
						out = append(out, ix.assignment(info, pkg, enc, kv, kv.Value, key))
					}
				case *ast.AssignStmt:
					for i, lhs := range e.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if !ok || i >= len(e.Rhs) {
							continue
						}
						if s, ok := info.Selections[sel]; !ok || !selObjMatch(s, ref) {
							continue
						}
						out = append(out, ix.assignment(info, pkg, enc, sel, e.Rhs[i], key))
					}
				}
				return true
			})
		}
	}
	return out, nil
}

func (ix *Index) assignment(info *types.Info, pkg *packages.Package, enc *ast.FuncDecl,
	node ast.Node, rhs ast.Expr, subject string) domain.ConfigAssignment {

	pos := ix.fset.Position(node.Pos())
	a := domain.ConfigAssignment{
		Subject: subject,
		CallSite: domain.CallSite{
			File:    pos.Filename,
			Line:    pos.Line,
			Package: pkg.PkgPath,
		},
	}
	if enc != nil && enc.Name != nil {
		a.Function = enc.Name.Name
	}
	a.Value, a.Source = exprConstValue(info, rhs)
	return a
}

// exprConstValue resolves an RHS expression to its constant value;
// source is "literal" for basic literals, "const" for named constants,
// "" when the value is not statically known.
func exprConstValue(info *types.Info, e ast.Expr) (string, string) {
	if tv, ok := info.Types[e]; ok && tv.Value != nil {
		v := tv.Value.String()
		if _, isLit := e.(*ast.BasicLit); isLit {
			return v, "literal"
		}
		// Predeclared idents (true/false) are literals, not named consts.
		if id, ok := e.(*ast.Ident); ok {
			if obj := info.ObjectOf(id); obj != nil && obj.Pkg() == nil {
				return v, "literal"
			}
		}
		return v, "const"
	}
	// Fallback for nodes types.Info did not fold (e.g. lit keys).
	if lit, ok := e.(*ast.BasicLit); ok {
		return strings.Trim(lit.Value, `"`), "literal"
	}
	return "", ""
}

// SymbolFieldType returns the underlying kind ("bool", "string", …) of a
// "Type.Field" subject — used to apply Go zero-value semantics when a
// knob is never assigned. Empty when the field or type cannot be resolved.
func (ix *Index) SymbolFieldType(ctx context.Context, ref domain.SymbolRef) (string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return "", err
	}
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" {
		return "", nil
	}
	find := func(pkgs []*packages.Package) string {
		for _, pkg := range pkgs {
			if pkg.PkgPath != ref.Package || pkg.Types == nil {
				continue
			}
			tn, ok := pkg.Types.Scope().Lookup(typeName).(*types.TypeName)
			if !ok {
				continue
			}
			st, ok := tn.Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}
			for i := 0; i < st.NumFields(); i++ {
				if st.Field(i).Name() == name {
					return st.Field(i).Type().Underlying().String()
				}
			}
		}
		return ""
	}
	if t := find(ix.pkgs); t != "" {
		return t, nil
	}
	extra, err := ix.loadExtra(ctx, ref.Package)
	if err != nil {
		return "", err
	}
	return find(extra), nil
}
