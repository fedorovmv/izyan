package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
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

// configRefRe matches identifier prefixes conventionally bound to
// configuration: cfg, config, opts, settings, env, flag.
var configRefRe = regexp.MustCompile(`(?i)^(cfg|config|opts?|settings?|env|flags?)[_.]?`)

// ConfigGated reports whether the statement at site sits inside an `if`
// whose condition reads configuration — os.Getenv/flag.* calls, idents
// assigned from them, or config-named fields (cfg.X, opts.Y). Reachability
// through such a site is conditional on a knob the analyzer may not have
// resolved: a guard/call under it cannot silently count as unconditional.
func (ix *Index) ConfigGated(ctx context.Context, site domain.CallSite) (bool, string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return false, "", err
	}
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			pos := ix.fset.Position(f.Pos())
			if pos.Filename != site.File {
				continue
			}
			enc := funcAt(ix.fset, f, site.Line)
			if enc == nil || enc.Body == nil {
				continue
			}
			gated := false
			var condSrc string
			ast.Inspect(enc.Body, func(n ast.Node) bool {
				ifs, ok := n.(*ast.IfStmt)
				if !ok || gated {
					return true
				}
				// Does the site's line live inside this if's branches?
				beg := ix.fset.Position(ifs.Body.Pos()).Line
				end := ix.fset.Position(ifs.End()).Line
				if site.Line < beg || site.Line > end {
					return true
				}
				if c := condConfigRef(ifs.Cond); c != "" {
					gated = true
					condSrc = fmt.Sprintf("%s:%d guarded by config condition %q",
						site.File, site.Line, c)
					return false
				}
				// Ident in cond assigned from a config read earlier in enc?
				for _, id := range condIdents(ifs.Cond) {
					if isConfigAssigned(enc.Body, id, pkg.TypesInfo) {
						gated = true
						condSrc = fmt.Sprintf("%s:%d guarded by config-bound %s",
							site.File, site.Line, id)
						return false
					}
				}
				return true
			})
			if gated {
				return true, condSrc, nil
			}
		}
	}
	return false, "", nil
}

// funcAt returns the function declaration whose body contains line.
func funcAt(fset *token.FileSet, f *ast.File, line int) *ast.FuncDecl {
	var hit *ast.FuncDecl
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fset.Position(fn.Pos()).Line <= line && line <= fset.Position(fn.End()).Line {
			hit = fn
		}
	}
	return hit
}

// condConfigRef reports a config-reading call inside a condition
// expression: os.Getenv / flag.* calls, or config-named selector roots.
func condConfigRef(cond ast.Expr) string {
	var found string
	ast.Inspect(cond, func(n ast.Node) bool {
		if found != "" {
			return false
		}
		switch e := n.(type) {
		case *ast.CallExpr:
			if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
				if x, ok2 := sel.X.(*ast.Ident); ok2 {
					if (x.Name == "os" && (sel.Sel.Name == "Getenv" || sel.Sel.Name == "LookupEnv")) ||
						x.Name == "flag" {
						found = x.Name + "." + sel.Sel.Name
						return false
					}
				}
			}
			if name := callName(e.Fun); name == "Getenv" || name == "LookupEnv" {
				found = name
				return false
			}
		case *ast.SelectorExpr:
			if id, ok := e.X.(*ast.Ident); ok && configRefRe.MatchString(id.Name) {
				found = id.Name + "." + e.Sel.Name
				return false
			}
		}
		return true
	})
	return found
}

// condIdents returns bare identifiers used in a condition expression.
func condIdents(cond ast.Expr) []string {
	var out []string
	ast.Inspect(cond, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			out = append(out, id.Name)
		}
		return true
	})
	return out
}

// isConfigAssigned reports whether ident id is assigned a config-reading
// expression anywhere in the function body (os.Getenv/flag.* call or a
// config-named selector).
func isConfigAssigned(body *ast.BlockStmt, id string, _ *types.Info) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			lid, ok := lhs.(*ast.Ident)
			if !ok || lid.Name != id || i >= len(as.Rhs) {
				continue
			}
			rhs := as.Rhs[i]
			if c := condConfigRef(rhs); c != "" {
				found = true
				return false
			}
			if s, ok2 := rhs.(*ast.StarExpr); ok2 {
				if id2, ok3 := s.X.(*ast.Ident); ok3 && configRefRe.MatchString(id2.Name) {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}
