package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
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
	return ix.fieldAssignmentsLocked(ref), nil
}

func (ix *Index) fieldAssignmentsLocked(ref domain.SymbolRef) []domain.ConfigAssignment {
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
	return out
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
	return ix.symbolFieldTypeLocked(ctx, ref), nil
}

func (ix *Index) symbolFieldTypeLocked(ctx context.Context, ref domain.SymbolRef) string {
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" {
		return ""
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
		return t
	}
	extra, err := ix.loadExtra(ctx, ref.Package)
	if err != nil {
		return ""
	}
	return find(extra)
}

// configRefRe matches identifier prefixes conventionally bound to
// configuration: cfg, config, opts, settings, env, flag, appcfg.
var configRefRe = regexp.MustCompile(`(?i)^(cfg|config|opts?|settings?|env|flags?|appcfg)[_.]?`)

// CheckCallSiteGuard inspects the statement at site to determine if it sits inside an if statement,
// and whether that guard condition is a configuration knob and/or statically dead code.
func (ix *Index) CheckCallSiteGuard(ctx context.Context, site domain.CallSite) (gated bool, deadCode bool, detail string, err error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return false, false, "", err
	}
	return ix.checkCallSiteGuardLocked(ctx, site)
}

// IsCallSiteDeadCode reports whether the call site sits inside a statically disabled feature gate or dead code.
func (ix *Index) IsCallSiteDeadCode(ctx context.Context, site domain.CallSite) (bool, string, error) {
	_, dead, detail, err := ix.CheckCallSiteGuard(ctx, site)
	return dead, detail, err
}

// ConfigGated reports whether the statement at site sits inside an `if`
// whose condition reads configuration — os.Getenv/flag.* calls, idents
// assigned from them, or config-named fields (cfg.X, opts.Y). Reachability
// through such a site is conditional on a knob the analyzer may not have
// resolved: a guard/call under it cannot silently count as unconditional.
func (ix *Index) ConfigGated(ctx context.Context, site domain.CallSite) (bool, string, error) {
	gated, _, detail, err := ix.CheckCallSiteGuard(ctx, site)
	return gated, detail, err
}

func (ix *Index) checkCallSiteGuardLocked(ctx context.Context, site domain.CallSite) (bool, bool, string, error) {
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			pos := ix.fset.Position(f.Pos())
			if pos.Filename != site.File && !strings.HasSuffix(pos.Filename, "/"+site.File) {
				continue
			}
			enc := funcAt(ix.fset, f, site.Line)
			if enc == nil || enc.Body == nil {
				continue
			}
			var gated, deadCode bool
			var condSrc string
			ast.Inspect(enc.Body, func(n ast.Node) bool {
				ifs, ok := n.(*ast.IfStmt)
				if !ok || gated || deadCode {
					return true
				}
				beg := ix.fset.Position(ifs.Body.Pos()).Line
				end := ix.fset.Position(ifs.End()).Line
				if site.Line < beg || site.Line > end {
					return true
				}
				gated, deadCode, condSrc = ix.evalGuardCondition(ctx, pkg, enc, ifs.Cond, site)
				return false
			})
			if gated || deadCode {
				return gated, deadCode, condSrc, nil
			}
		}
	}
	return false, false, "", nil
}

func (ix *Index) evalGuardCondition(ctx context.Context, pkg *packages.Package, enc *ast.FuncDecl, cond ast.Expr, site domain.CallSite) (bool, bool, string) {
	if pkg.TypesInfo != nil {
		if tv, ok := pkg.TypesInfo.Types[cond]; ok && tv.Value != nil && tv.Value.Kind() == constant.Bool {
			if !constant.BoolVal(tv.Value) {
				return true, true, fmt.Sprintf("%s:%d guarded by constant false", site.File, site.Line)
			}
			return false, false, ""
		}
	}

	if un, ok := cond.(*ast.UnaryExpr); ok && un.Op == token.NOT {
		g, d, detail := ix.evalGuardCondition(ctx, pkg, enc, un.X, site)
		if g && d {
			return true, false, detail
		}
		return g, false, detail
	}

	if sel, ok := cond.(*ast.SelectorExpr); ok {
		return ix.evalSelectorGuard(ctx, pkg, enc, sel, site)
	}

	if id, ok := cond.(*ast.Ident); ok {
		var hitRhs ast.Expr
		ast.Inspect(enc.Body, func(n ast.Node) bool {
			if hitRhs != nil {
				return false
			}
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for i, lhs := range as.Lhs {
				if li, ok := lhs.(*ast.Ident); ok && li.Name == id.Name && i < len(as.Rhs) {
					hitRhs = as.Rhs[i]
					return false
				}
			}
			return true
		})
		if hitRhs != nil {
			if lit, ok := hitRhs.(*ast.BasicLit); ok && lit.Value == "false" {
				return true, true, fmt.Sprintf("%s:%d guarded by %s = false", site.File, site.Line, id.Name)
			}
			if rsel, ok := hitRhs.(*ast.SelectorExpr); ok {
				return ix.evalSelectorGuard(ctx, pkg, enc, rsel, site)
			}
			if isConfigAssigned(enc.Body, id.Name, pkg.TypesInfo) {
				return true, false, fmt.Sprintf("%s:%d guarded by config-bound %s", site.File, site.Line, id.Name)
			}
		}
	}

	if c := condConfigRef(cond); c != "" {
		return true, false, fmt.Sprintf("%s:%d guarded by config condition %q", site.File, site.Line, c)
	}
	for _, id := range condIdents(cond) {
		if isConfigAssigned(enc.Body, id, pkg.TypesInfo) {
			return true, false, fmt.Sprintf("%s:%d guarded by config-bound %s", site.File, site.Line, id)
		}
	}
	return false, false, ""
}

func (ix *Index) evalSelectorGuard(ctx context.Context, pkg *packages.Package, enc *ast.FuncDecl, sel *ast.SelectorExpr, site domain.CallSite) (bool, bool, string) {
	fieldName := sel.Sel.Name
	var typeName, pkgPath string
	if seln, ok := pkg.TypesInfo.Selections[sel]; ok {
		recv := seln.Recv()
		if p, ok := recv.(*types.Pointer); ok {
			recv = p.Elem()
		}
		if named, ok := recv.(*types.Named); ok {
			typeName = named.Obj().Name()
			if named.Obj().Pkg() != nil {
				pkgPath = named.Obj().Pkg().Path()
			}
		}
	}
	if typeName == "" {
		if tv, ok := pkg.TypesInfo.Types[sel.X]; ok && tv.Type != nil {
			recv := tv.Type
			if p, ok := recv.(*types.Pointer); ok {
				recv = p.Elem()
			}
			if named, ok := recv.(*types.Named); ok {
				typeName = named.Obj().Name()
				if named.Obj().Pkg() != nil {
					pkgPath = named.Obj().Pkg().Path()
				}
			}
		}
	}

	if typeName != "" {
		ref := domain.SymbolRef{Package: pkgPath, Symbol: typeName + "." + fieldName}
		fieldType := ix.symbolFieldTypeLocked(ctx, ref)
		if fieldType == "bool" {
			assigns := ix.fieldAssignmentsLocked(ref)
			if len(assigns) == 0 {
				return true, true, fmt.Sprintf("%s:%d guarded by %s.%s (zero-value false)", site.File, site.Line, typeName, fieldName)
			}
			allFalse := true
			anyStatic := false
			for _, a := range assigns {
				if a.Value == "true" {
					allFalse = false
				} else if a.Value == "false" {
					anyStatic = true
				} else {
					allFalse = false
				}
			}
			if allFalse && anyStatic {
				return true, true, fmt.Sprintf("%s:%d guarded by %s.%s (statically false)", site.File, site.Line, typeName, fieldName)
			}
			return true, false, fmt.Sprintf("%s:%d guarded by config condition %s.%s", site.File, site.Line, typeName, fieldName)
		}
	}

	if c := condConfigRef(sel); c != "" {
		return true, false, fmt.Sprintf("%s:%d guarded by config condition %q", site.File, site.Line, c)
	}
	return false, false, ""
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
