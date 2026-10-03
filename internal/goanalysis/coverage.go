package goanalysis

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// GatedRefs scans source files excluded by the current build
// configuration (pkg.IgnoredFiles, minus _test.go) for syntactic
// references to the subject. A hit does not prove a path — the file may
// be dead code — but it means a build with different tags could reach
// the subject, so a negative claim cannot be called verified within the
// current scope.
func (ix *Index) GatedRefs(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	typeName, name := splitSymbol(ref.Symbol)
	seen := map[string]bool{}
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		for _, path := range pkg.IgnoredFiles {
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || seen[path] {
				continue
			}
			seen[path] = true
			f, err := parser.ParseFile(ix.fset, path, nil, 0)
			if err != nil {
				continue
			}
			out = append(out, gatedFileRefs(ix.fset, pkg, f, ref, typeName, name)...)
		}
	}
	return out, nil
}

// gatedFileRefs matches subject references in an untyped file: the file
// must import the subject's package; bare-name subjects match
// `alias.Name`, Type.Method subjects match `alias.Type` uses plus
// `.Method` selectors when the file also references the type.
func gatedFileRefs(fset *token.FileSet, pkg *packages.Package, f *ast.File,
	ref domain.SymbolRef, typeName, name string) []domain.CallSite {

	aliases := map[string]bool{}
	for _, imp := range f.Imports {
		if strings.Trim(imp.Path.Value, `"`) != ref.Package {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "." {
				aliases[""] = true // dot import: bare identifier use
			} else {
				aliases[imp.Name.Name] = true
			}
		} else {
			aliases[path.Base(ref.Package)] = true
		}
	}
	if len(aliases) == 0 {
		return nil
	}
	typeReferenced := typeName == "" || aliases[""]
	var enc *ast.FuncDecl
	var out []domain.CallSite
	site := func(n ast.Node) {
		pos := fset.Position(n.Pos())
		cs := domain.CallSite{File: pos.Filename, Line: pos.Line, Package: pkg.PkgPath}
		if enc != nil && enc.Name != nil {
			cs.Function = enc.Name.Name
		}
		out = append(out, cs)
	}
	// First pass: does the file reference the declaring type? Without it
	// an `x.Method` selector cannot plausibly reach the subject.
	if typeName != "" && !typeReferenced {
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if ok && aliases[id.Name] && sel.Sel.Name == typeName {
				typeReferenced = true
			}
			return !typeReferenced
		})
	}
	ast.Inspect(f, func(n ast.Node) bool {
		if fn, ok := n.(*ast.FuncDecl); ok {
			enc = fn
		}
		switch e := n.(type) {
		case *ast.SelectorExpr:
			id, ok := e.X.(*ast.Ident)
			if ok && aliases[id.Name] && (e.Sel.Name == name || e.Sel.Name == typeName) {
				site(e)
				return true
			}
			if typeName != "" && typeReferenced && e.Sel.Name == name {
				site(e)
			}
		case *ast.Ident:
			if aliases[""] && e.Name == name {
				site(e)
			}
		}
		return true
	})
	return out
}

// InterfaceDispatchSites finds product call sites `x.Method()` where x
// is statically an interface type and the subject's receiver type
// implements that interface. SearchSymbol misses these: the selection
// resolves to the interface method, not to Type.Method. Each site is a
// dispatch candidate — the concrete impl behind the interface may be the
// subject's type, so a negative reachability claim over these sites is
// not closed.
func (ix *Index) InterfaceDispatchSites(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" {
		return nil, nil // plain functions cannot be interface-dispatched
	}
	recv := ix.lookupNamedType(ctx, ref.Package, typeName)
	if recv == nil {
		return nil, nil
	}
	var out []domain.CallSite
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
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				seln, ok := info.Selections[sel]
				if !ok || seln.Kind() != types.MethodVal || seln.Obj().Name() != name {
					return true
				}
				iface, ok := seln.Recv().Underlying().(*types.Interface)
				if !ok {
					return true // concrete receiver — SearchSymbol already covers
				}
				// Skip when the interface method itself IS the subject
				// (declared in the subject's package): such calls are the
				// subject, not a dispatch candidate.
				if fn := seln.Obj().(*types.Func); fn.Pkg() != nil && fn.Pkg().Path() == ref.Package {
					return true
				}
				if !types.Implements(recv, iface) && !types.Implements(types.NewPointer(recv), iface) {
					return true
				}
				pos := ix.fset.Position(sel.Pos())
				cs := domain.CallSite{
					File:    pos.Filename,
					Line:    pos.Line,
					Package: pkg.PkgPath,
				}
				if enc != nil && enc.Name != nil {
					cs.Function = enc.Name.Name
				}
				out = append(out, cs)
				return true
			})
		}
	}
	return out, nil
}

// lookupNamedType resolves a named type in pkgPath, searching product
// roots first and falling back to loading the package directly.
func (ix *Index) lookupNamedType(ctx context.Context, pkgPath, typeName string) *types.Named {
	find := func(pkgs []*packages.Package) *types.Named {
		for _, pkg := range pkgs {
			if pkg.PkgPath != pkgPath || pkg.Types == nil {
				continue
			}
			if tn, ok := pkg.Types.Scope().Lookup(typeName).(*types.TypeName); ok {
				if named, ok := tn.Type().(*types.Named); ok {
					return named
				}
			}
		}
		return nil
	}
	if t := find(ix.pkgs); t != nil {
		return t
	}
	extra, err := ix.loadExtra(ctx, pkgPath)
	if err != nil {
		return nil
	}
	return find(extra)
}
