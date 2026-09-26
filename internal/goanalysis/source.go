package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/tools/go/packages"

	"example.com/vuln-analyzer/internal/domain"
)

// Index is a lazily loaded go/packages view of the analyzed product.
// It backs the targeted source tools (find_symbol, find_callers,
// read_function, find_entrypoints, argument provenance).
type Index struct {
	Dir     string
	Build   domain.ProductSnapshot
	mu      sync.Mutex // serializes queries; shared across cases in scan mode
	pkgs    []*packages.Package
	fset    *token.FileSet
	loaded  bool
	loadErr error
}

// buildEnv derives GOOS/GOARCH/CGO env for tool invocations.
func buildEnv(build domain.ProductSnapshot) []string {
	var env []string
	if build.GOOS != "" {
		env = append(env, "GOOS="+build.GOOS)
	}
	if build.GOARCH != "" {
		env = append(env, "GOARCH="+build.GOARCH)
	}
	env = append(env, "CGO_ENABLED="+strconv.FormatBool(build.CGOEnabled))
	return env
}

const loadMode = packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
	packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports |
	packages.NeedDeps | packages.NeedModule

func (ix *Index) load(ctx context.Context) error {
	if ix.loaded {
		return ix.loadErr
	}
	ix.loaded = true
	ix.fset = token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  ix.Dir,
		Fset: ix.fset,
		Env:  append(os.Environ(), buildEnv(ix.Build)...),
	}
	if len(ix.Build.BuildTags) > 0 {
		cfg.BuildFlags = []string{"-tags", strings.Join(ix.Build.BuildTags, ",")}
	}
	ix.pkgs, ix.loadErr = packages.Load(cfg, "./...")
	if ix.loadErr == nil && packages.PrintErrors(ix.pkgs) > 0 {
		ix.loadErr = fmt.Errorf("package loading produced errors (incomplete type information)")
	}
	return ix.loadErr
}

// loadExtra loads additional root patterns (e.g. the vulnerable dependency
// package) into the same fileset so its syntax is available for reading.
func (ix *Index) loadExtra(ctx context.Context, patterns ...string) ([]*packages.Package, error) {
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  ix.Dir,
		Fset: ix.fset,
		Env:  append(os.Environ(), buildEnv(ix.Build)...),
	}
	if len(ix.Build.BuildTags) > 0 {
		cfg.BuildFlags = []string{"-tags", strings.Join(ix.Build.BuildTags, ",")}
	}
	return packages.Load(cfg, patterns...)
}

// Loaded reports whether the index can answer structural queries; if false,
// callers must treat results as tool failures (UNKNOWN, never FALSE inputs).
func (ix *Index) Loaded(ctx context.Context) error {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.load(ctx)
}

// FindSymbol locates a symbol (function or method) by package path and name.
// The name may be "Func" or "Type.Method"/"(*Type).Method".
func (ix *Index) FindSymbol(ctx context.Context, ref domain.SymbolRef) (*domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.findSymbol(ctx, ref)
}

func (ix *Index) findSymbol(ctx context.Context, ref domain.SymbolRef) (*domain.CallSite, error) {
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	typeName, meth := splitSymbol(ref.Symbol)
	for _, pkg := range ix.pkgs {
		if pkg.Types == nil {
			continue
		}
		if pkg.PkgPath != ref.Package {
			continue
		}
		if cs := findObjectInPkg(ix.fset, pkg, typeName, meth); cs != nil {
			return cs, nil
		}
	}
	// symbol may live in a dependency that is not a loaded root
	extra, err := ix.loadExtra(ctx, ref.Package)
	if err != nil {
		return nil, err
	}
	for _, pkg := range extra {
		if pkg.PkgPath != ref.Package || pkg.Types == nil {
			continue
		}
		if cs := findObjectInPkg(ix.fset, pkg, typeName, meth); cs != nil {
			return cs, nil
		}
	}
	return nil, fmt.Errorf("symbol %s.%s not found", ref.Package, ref.Symbol)
}

func splitSymbol(sym string) (typeName, name string) {
	s := strings.TrimPrefix(sym, "*")
	if i := strings.Index(s, "."); i >= 0 {
		return s[:i], s[i+1:]
	}
	return "", sym
}

func findObjectInPkg(fset *token.FileSet, pkg *packages.Package, typeName, name string) *domain.CallSite {
	if typeName == "" {
		if obj := pkg.Types.Scope().Lookup(name); obj != nil {
			return callSiteFor(fset, pkg, obj)
		}
		// Bare name may be a method whose receiver the caller did not
		// preserve (e.g. "recvContent" for (*Channel).recvContent).
		return findMethodInPkg(fset, pkg, name)
	}
	tn := pkg.Types.Scope().Lookup(typeName)
	if tn == nil {
		return nil
	}
	named, ok := tn.(*types.TypeName)
	if !ok {
		return nil
	}
	for _, obj := range []*types.Named{mustNamed(named)} {
		if obj == nil {
			continue
		}
		for i := 0; i < obj.NumMethods(); i++ {
			m := obj.Method(i)
			if m.Name() == name {
				return callSiteFor(fset, pkg, m)
			}
		}
		// Struct fields resolve as symbols too — presence checks for
		// sensitive data ("Config.SASL") name fields, not methods.
		if st, ok := obj.Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				if st.Field(i).Name() == name {
					return callSiteFor(fset, pkg, st.Field(i))
				}
			}
		}
	}
	return nil
}

// findMethodInPkg locates a uniquely-named method across all named
// types in the package. Multiple matches are ambiguous -> nil, so the
// caller reports the candidate as unverified rather than guessing.
func findMethodInPkg(fset *token.FileSet, pkg *packages.Package, name string) *domain.CallSite {
	var found *domain.CallSite
	for _, n := range pkg.Types.Scope().Names() {
		tn, ok := pkg.Types.Scope().Lookup(n).(*types.TypeName)
		if !ok {
			continue
		}
		nt := mustNamed(tn)
		if nt == nil {
			continue
		}
		for i := 0; i < nt.NumMethods(); i++ {
			if nt.Method(i).Name() == name {
				if found != nil {
					return nil
				}
				found = callSiteFor(fset, pkg, nt.Method(i))
			}
		}
	}
	return found
}

func mustNamed(tn *types.TypeName) *types.Named {
	if n, ok := tn.Type().(*types.Named); ok {
		return n
	}
	return nil
}

func callSiteFor(fset *token.FileSet, pkg *packages.Package, obj types.Object) *domain.CallSite {
	pos := fset.Position(obj.Pos())
	return &domain.CallSite{
		File:     pos.Filename,
		Line:     pos.Line,
		Function: obj.Name(),
		Package:  pkg.PkgPath,
	}
}

// SearchSymbol returns every reference to the symbol inside product
// packages — direct calls, value references (assignments, interface
// satisfaction candidates), qualified type names, and for field-qualified
// subjects ("Type.Field") field selections and composite-literal keys.
func (ix *Index) SearchSymbol(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			// Selector .Sel idents and composite-literal field keys are
			// matched at their parent nodes, where the receiver/literal
			// type can disambiguate which struct declares the field.
			skip := map[*ast.Ident]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.SelectorExpr:
					skip[e.Sel] = true
				case *ast.CompositeLit:
					for _, elt := range e.Elts {
						if kv, ok := elt.(*ast.KeyValueExpr); ok {
							if id, ok := kv.Key.(*ast.Ident); ok {
								skip[id] = true
							}
						}
					}
				}
				return true
			})
			var enc *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enc = fn
				}
				match := false
				switch e := n.(type) {
				case *ast.Ident:
					if !skip[e] {
						match = symRefIdent(info, e, ref)
					}
				case *ast.SelectorExpr:
					match = selRefMatch(info, e, ref)
				case *ast.CompositeLit:
					match = litFieldMatch(info, e, ref)
				}
				if !match {
					return true
				}
				site := domain.CallSite{
					File:    ix.fset.Position(n.Pos()).Filename,
					Line:    ix.fset.Position(n.Pos()).Line,
					Package: pkg.PkgPath,
				}
				if enc != nil && enc.Name != nil {
					site.Function = enc.Name.Name
				}
				out = append(out, site)
				return true
			})
		}
	}
	return out, nil
}

// CallSiteRef pairs the exported CallSite with its internal AST handle.
type CallSiteRef struct {
	Site      domain.CallSite
	call      *ast.CallExpr
	enclosing *ast.FuncDecl
	pkg       *packages.Package
}

// FindCallers returns statically resolved call sites of the symbol inside
// the product packages (loaded ./... roots).
func (ix *Index) FindCallers(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	refs, err := ix.findCallSites(ctx, ref)
	if err != nil {
		return nil, err
	}
	out := make([]domain.CallSite, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Site)
	}
	return out, nil
}

func (ix *Index) findCallSites(ctx context.Context, ref domain.SymbolRef) ([]CallSiteRef, error) {
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []CallSiteRef
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			var enc *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enc = fn
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if callIsSymbol(info, call.Fun, ref) {
					site := ix.siteOf(pkg, enc, call)
					out = append(out, CallSiteRef{Site: site, call: call, enclosing: enc, pkg: pkg})
				}
				return true
			})
		}
	}
	return out, nil
}

func callIsSymbol(info *types.Info, fun ast.Expr, ref domain.SymbolRef) bool {
	obj := calleeObject(info, fun)
	fn, ok := obj.(*types.Func)
	if !ok || fn.Pkg() == nil {
		return false
	}
	if fn.Pkg().Path() != ref.Package {
		return false
	}
	typeName, name := splitSymbol(ref.Symbol)
	if fn.Name() != name {
		return false
	}
	if typeName == "" {
		return true
	}
	sig, _ := fn.Type().(*types.Signature)
	if sig == nil || sig.Recv() == nil {
		return false
	}
	return recvTypeName(sig.Recv().Type()) == typeName
}

func calleeObject(info *types.Info, fun ast.Expr) types.Object {
	switch e := fun.(type) {
	case *ast.Ident:
		return info.ObjectOf(e)
	case *ast.SelectorExpr:
		if sel, ok := info.Selections[e]; ok {
			return sel.Obj()
		}
		return info.ObjectOf(e.Sel)
	}
	return nil
}

func recvTypeName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

func (ix *Index) siteOf(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr) domain.CallSite {
	pos := ix.fset.Position(call.Lparen)
	site := domain.CallSite{
		File:    pos.Filename,
		Line:    pos.Line,
		Column:  pos.Column,
		Package: pkg.PkgPath,
	}
	if enc != nil && enc.Name != nil {
		site.Function = enc.Name.Name
	}
	return site
}

// ReadFunction returns the source text of the function enclosing pos or
// matching name in the given file.
func (ix *Index) ReadFunction(ctx context.Context, file, funcName string) (string, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return "", err
	}
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			fpos := ix.fset.Position(f.Pos())
			if fpos.Filename != file {
				continue
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || (funcName != "" && fn.Name.Name != funcName) {
					continue
				}
				return ix.nodeSource(fn)
			}
		}
	}
	return "", fmt.Errorf("function %s not found in %s", funcName, file)
}

func (ix *Index) nodeSource(n ast.Node) (string, error) {
	start := ix.fset.Position(n.Pos())
	end := ix.fset.Position(n.End())
	b, err := os.ReadFile(start.Filename)
	if err != nil {
		return "", err
	}
	if start.Offset < 0 || end.Offset > len(b) {
		return "", fmt.Errorf("offsets out of range")
	}
	return string(b[start.Offset:end.Offset]), nil
}

// FindEntrypoints enumerates plausible external entrypoints in product
// packages: main/init functions and net/http handlers.
func (ix *Index) FindEntrypoints(ctx context.Context) ([]domain.Entrypoint, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.Entrypoint
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				kind := entrypointKind(pkg, fn)
				if kind == "" {
					continue
				}
				pos := ix.fset.Position(fn.Pos())
				out = append(out, domain.Entrypoint{
					CallSite: domain.CallSite{
						File:     pos.Filename,
						Line:     pos.Line,
						Function: fn.Name.Name,
						Package:  pkg.PkgPath,
					},
					Kind:    kind,
					Exposed: ast.IsExported(fn.Name.Name) || kind != "export",
				})
			}
		}
	}
	return out, nil
}

func entrypointKind(pkg *packages.Package, fn *ast.FuncDecl) string {
	switch {
	case pkg.Name == "main" && fn.Name.Name == "main":
		return "main"
	case fn.Name.Name == "init":
		return "init"
	case isHTTPHandler(pkg, fn):
		return "http"
	}
	return ""
}

func isHTTPHandler(pkg *packages.Package, fn *ast.FuncDecl) bool {
	if fn.Type.Params == nil || fn.Type.Params.NumFields() != 2 {
		return false
	}
	info := pkg.TypesInfo
	var sawWriter, sawRequest bool
	for _, field := range fn.Type.Params.List {
		t := info.TypeOf(field.Type)
		if t == nil {
			continue
		}
		s := t.String()
		if strings.HasSuffix(s, "http.ResponseWriter") {
			sawWriter = true
		}
		if strings.HasSuffix(s, "*http.Request") {
			sawRequest = true
		}
	}
	return sawWriter && sawRequest
}

// listenerPrimitives are calls that make the product accept inbound network
// connections. A product function containing one is a "listener" entrypoint:
// bytes consumed by a reachable server-side transport originate from remote
// peers, not from product code.
var listenerPrimitives = []domain.SymbolRef{
	{Package: "net", Symbol: "Listen"},
	{Package: "net", Symbol: "ListenTCP"},
	{Package: "net", Symbol: "ListenUDP"},
	{Package: "net", Symbol: "Listener.Accept"},
	{Package: "net/http", Symbol: "ListenAndServe"},
	{Package: "net/http", Symbol: "ListenAndServeTLS"},
	{Package: "net/http", Symbol: "Server.Serve"},
	{Package: "net/http", Symbol: "Server.ListenAndServe"},
	{Package: "google.golang.org/grpc", Symbol: "NewServer"},
	{Package: "google.golang.org/grpc", Symbol: "Server.Serve"},
	{Package: "google.golang.org/grpc", Symbol: "Server.ServeHTTP"},
}

// FindListeners reports product functions that start network listeners or
// servers — i.e. functions whose body calls a listener primitive.
func (ix *Index) FindListeners(ctx context.Context) ([]domain.Entrypoint, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.Entrypoint
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				matched := ""
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if matched != "" {
						return false
					}
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					for _, prim := range listenerPrimitives {
						if callIsSymbol(info, call.Fun, prim) {
							matched = prim.Package + "." + prim.Symbol
							return false
						}
					}
					return true
				})
				if matched == "" {
					continue
				}
				pos := ix.fset.Position(fn.Pos())
				out = append(out, domain.Entrypoint{
					CallSite: domain.CallSite{
						File:     pos.Filename,
						Line:     pos.Line,
						Function: fn.Name.Name,
						Package:  pkg.PkgPath,
					},
					Kind:    "listener",
					Detail:  matched,
					Exposed: true,
				})
			}
		}
	}
	return out, nil
}

// ModuleUsage reports product call sites into any package of the given
// module ("github.com/rabbitmq/amqp091-go" covers ".../amqp091-go/spec091"
// too). When a vulnerability's sinks are library internals that only execute
// while the library handles peer input, module usage is evidence that the
// vulnerable code paths run — product code can never name the unexported
// symbols directly.
func (ix *Index) ModuleUsage(ctx context.Context, module string) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.CallSite
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			var enc *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enc = fn
				}
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				obj := calleeObject(info, call.Fun)
				fn, ok := obj.(*types.Func)
				if !ok || fn.Pkg() == nil {
					return true
				}
				p := fn.Pkg().Path()
				if p != module && !strings.HasPrefix(p, module+"/") {
					return true
				}
				site := ix.siteOf(pkg, enc, call)
				site.Callee = p + "." + fn.Name()
				if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
					rn := strings.TrimPrefix(sig.Recv().Type().String(), "*")
					if i := strings.LastIndexByte(rn, '.'); i >= 0 {
						rn = rn[i+1:]
					}
					site.Callee = p + "." + rn + "." + fn.Name()
				}
				out = append(out, site)
				return true
			})
		}
	}
	return out, nil
}

// ModuleInternalReach resolves which of the given subjects are reachable from
// the entry symbols (module API functions the product calls) through call
// edges inside the vendored module source. Returns subject key ("pkg.Symbol")
// to the discovered call chain (entry → ... → subject). Type-resolved: method
// calls match the subject only when the receiver type is the subject's.
func (ix *Index) ModuleInternalReach(ctx context.Context, module string, entries []string, subjects []domain.SymbolRef) (map[string][]string, error) {
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode: loadMode,
		Dir:  ix.Dir,
		Fset: fset,
		Env:  append(os.Environ(), buildEnv(ix.Build)...),
	}
	pkgs, err := packages.Load(cfg, module+"/...")
	if err != nil {
		return nil, err
	}

	// caller-qualified-name -> set of callee-qualified-names within the module.
	edges := map[string]map[string]bool{}
	for _, pkg := range pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			var caller string
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok && fn.Name != nil {
					caller = fn.Name.Name
					if fn.Recv != nil && len(fn.Recv.List) > 0 {
						caller = recvDeclName(fn.Recv.List[0].Type) + "." + fn.Name.Name
					}
					return true
				}
				call, ok := n.(*ast.CallExpr)
				if !ok || caller == "" {
					return true
				}
				obj := calleeObject(info, call.Fun)
				fn, ok := obj.(*types.Func)
				if !ok || fn.Pkg() == nil {
					return true
				}
				p := fn.Pkg().Path()
				if p != module && !strings.HasPrefix(p, module+"/") {
					return true
				}
				callee := p + "." + fn.Name()
				if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
					callee = p + "." + recvTypeName(sig.Recv().Type()) + "." + fn.Name()
				}
				key := pkg.PkgPath + "." + caller
				if edges[key] == nil {
					edges[key] = map[string]bool{}
				}
				edges[key][callee] = true
				return true
			})
		}
	}

	out := map[string][]string{}
	for _, subj := range subjects {
		target := subj.Package + "." + subj.Symbol
		for _, e := range entries {
			if chain := bfsChain(edges, e, target); chain != nil {
				out[target] = chain
				break
			}
		}
	}
	return out, nil
}

func recvDeclName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.StarExpr:
		return recvDeclName(t.X)
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		return t.Sel.Name
	case *ast.IndexExpr, *ast.IndexListExpr:
		// generic receivers
		if x := ast.Unparen(expr); x != nil {
			if id, ok := baseIdent(x); ok {
				return id.Name
			}
		}
	}
	return ""
}

func baseIdent(e ast.Expr) (*ast.Ident, bool) {
	switch t := e.(type) {
	case *ast.Ident:
		return t, true
	case *ast.StarExpr:
		return baseIdent(t.X)
	case *ast.IndexExpr:
		return baseIdent(t.X)
	case *ast.IndexListExpr:
		return baseIdent(t.X)
	case *ast.SelectorExpr:
		return t.Sel, true
	}
	return nil, false
}

// bfsChain finds a caller->...->target chain in the intra-module call graph.
func bfsChain(edges map[string]map[string]bool, start, target string) []string {
	type node struct {
		name string
		prev *node
	}
	seen := map[string]bool{start: true}
	queue := []*node{{name: start}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.name == target {
			var chain []string
			for n := cur; n != nil; n = n.prev {
				chain = append(chain, n.name)
			}
			for i, j := 0, len(chain)-1; i < j; i, j = i+1, j-1 {
				chain[i], chain[j] = chain[j], chain[i]
			}
			return chain
		}
		for next := range edges[cur.name] {
			if !seen[next] {
				seen[next] = true
				queue = append(queue, &node{name: next, prev: cur})
			}
		}
	}
	return nil
}

// DynamicMarker describes language features that can bypass static
// call-graph reasoning: reflect, unsafe, plugins, linkname, function values
// referencing the analyzed symbol, etc.
type DynamicMarker struct {
	domain.CallSite
	Kind   string `json:"kind"` // reflect|unsafe|plugin|linkname|func_value|goroutine
	Detail string `json:"detail"`
}

// ScanDynamic finds dynamic-dispatch risk markers inside product packages.
func (ix *Index) ScanDynamic(ctx context.Context, ref domain.SymbolRef) ([]DynamicMarker, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []DynamicMarker
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			pos := func(n ast.Node) domain.CallSite {
				p := ix.fset.Position(n.Pos())
				return domain.CallSite{File: p.Filename, Line: p.Line, Package: pkg.PkgPath}
			}
			for _, imp := range f.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				switch path {
				case "reflect":
					out = append(out, DynamicMarker{CallSite: pos(imp), Kind: "reflect", Detail: "reflect import"})
				case "unsafe":
					out = append(out, DynamicMarker{CallSite: pos(imp), Kind: "unsafe", Detail: "unsafe import"})
				case "plugin":
					out = append(out, DynamicMarker{CallSite: pos(imp), Kind: "plugin", Detail: "plugin import"})
				}
			}
			callFuns := map[ast.Node]bool{}
			ast.Inspect(f, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					callFuns[call.Fun] = true
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						callFuns[sel.Sel] = true
					}
				}
				return true
			})
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.Comment:
					if strings.Contains(n.Text, "go:linkname") {
						out = append(out, DynamicMarker{CallSite: pos(n), Kind: "linkname", Detail: n.Text})
					}
				case *ast.Ident:
					if callFuns[n] {
						return true
					}
					if symRefIdent(pkg.TypesInfo, n, ref) {
						out = append(out, DynamicMarker{
							CallSite: pos(n), Kind: "func_value",
							Detail: "symbol referenced as value (may be invoked indirectly)",
						})
					}
				}
				return true
			})
		}
	}
	return out, nil
}

// symRefIdent reports whether ident references the target symbol without
// being part of a call expression fun position (i.e. used as a value).
// Beyond functions it matches qualified type names and package-level
// vars — field accesses are resolved precisely at their SelectorExpr /
// CompositeLiteral parents, never here.
func symRefIdent(info *types.Info, id *ast.Ident, ref domain.SymbolRef) bool {
	obj := info.ObjectOf(id)
	typeName, name := splitSymbol(ref.Symbol)
	switch o := obj.(type) {
	case *types.Func:
		if o.Pkg() == nil || o.Pkg().Path() != ref.Package {
			return false
		}
		return o.Name() == name
	case *types.TypeName, *types.Const:
		// "PlainAuth" in vuln.PlainAuth — the type name alone matches only
		// unqualified subjects; "Type.Field" subjects bind the member.
		if typeName != "" {
			return false
		}
		if o.Pkg() == nil || o.Pkg().Path() != ref.Package {
			return false
		}
		return o.Name() == name
	case *types.Var:
		if o.IsField() || typeName != "" {
			return false
		}
		if o.Pkg() == nil || o.Pkg().Path() != ref.Package {
			return false
		}
		return o.Name() == name
	}
	return false
}

// selRefMatch matches a selector expression against the subject: a
// selection (x.Field / x.Method) is checked against the declaring struct,
// a qualified identifier (pkg.Name) follows the bare-ident rules.
func selRefMatch(info *types.Info, e *ast.SelectorExpr, ref domain.SymbolRef) bool {
	if seln, ok := info.Selections[e]; ok {
		return selObjMatch(seln, ref)
	}
	return symRefIdent(info, e.Sel, ref)
}

// selObjMatch matches a resolved selection (field or method value) against
// a "Type.Name" subject by the declaring struct's name.
func selObjMatch(seln *types.Selection, ref domain.SymbolRef) bool {
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" {
		return false
	}
	obj := seln.Obj()
	if obj.Pkg() == nil || obj.Pkg().Path() != ref.Package || obj.Name() != name {
		return false
	}
	switch seln.Kind() {
	case types.FieldVal:
		return declaringStructName(seln) == typeName
	case types.MethodVal, types.MethodExpr:
		return recvTypeName(seln.Recv()) == typeName
	}
	return false
}

// declaringStructName resolves which struct along a (possibly embedded)
// selection path declares the selected field — "x.Password" promoted from
// an embedded PlainAuth reports PlainAuth, not the outer struct.
func declaringStructName(seln *types.Selection) string {
	t := seln.Recv()
	idx := seln.Index()
	for _, i := range idx[:len(idx)-1] {
		st, ok := derefStruct(t)
		if !ok {
			return recvTypeName(seln.Recv())
		}
		t = st.Field(i).Type()
	}
	return recvTypeName(t)
}

func derefStruct(t types.Type) (*types.Struct, bool) {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	st, ok := t.Underlying().(*types.Struct)
	return st, ok
}

// litFieldMatch matches a composite literal field key ("Type{Field: v}")
// against a "Type.Field" subject — the key ident's object alone cannot
// name its declaring struct, so the literal's type does it.
func litFieldMatch(info *types.Info, lit *ast.CompositeLit, ref domain.SymbolRef) bool {
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" {
		return false
	}
	n := namedOf(info.TypeOf(lit))
	if n == nil || n.Obj() == nil || n.Obj().Pkg() == nil ||
		n.Obj().Pkg().Path() != ref.Package || n.Obj().Name() != typeName {
		return false
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if id, ok := kv.Key.(*ast.Ident); ok && id.Name == name {
			return true
		}
	}
	return false
}

func namedOf(t types.Type) *types.Named {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	n, _ := t.(*types.Named)
	return n
}

// sensitiveFieldRe names struct fields that plausibly hold credentials —
// used by the INFO_LEAK datum pool, not by any verdict logic.
var sensitiveFieldRe = regexp.MustCompile(`(?i)password|passwd|secret|token|api[-_]?key|credential|sasl|session|cookie|private[-_]?key`)

// SensitiveFields returns "Type.Field" references for every exported,
// credential-named field declared in package pkgPath — the deterministic
// datum source for INFO_LEAK patterns. The dependency package is loaded
// on demand like any other symbol lookup.
func (ix *Index) SensitiveFields(ctx context.Context, pkgPath string) ([]domain.SymbolRef, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	pkg := ix.pkgByPath(ctx, pkgPath)
	if pkg == nil || pkg.Types == nil {
		return nil, fmt.Errorf("package %s not loaded", pkgPath)
	}
	var out []domain.SymbolRef
	for _, name := range pkg.Types.Scope().Names() {
		tn, ok := pkg.Types.Scope().Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		named := mustNamed(tn)
		if named == nil {
			continue
		}
		st, ok := named.Underlying().(*types.Struct)
		if !ok {
			continue
		}
		for i := 0; i < st.NumFields(); i++ {
			f := st.Field(i)
			if f.Exported() && sensitiveFieldRe.MatchString(f.Name()) {
				out = append(out, domain.SymbolRef{Package: pkgPath, Symbol: name + "." + f.Name()})
			}
		}
	}
	return out, nil
}

// IsStruct reports whether a bare package-level name resolves to a struct
// type — distinguishes a data carrier ("PlainAuth") from a sink function
// when advisory symbols are unqualified.
func (ix *Index) IsStruct(ctx context.Context, ref domain.SymbolRef) (bool, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return false, err
	}
	pkg := ix.pkgByPath(ctx, ref.Package)
	if pkg == nil || pkg.Types == nil {
		return false, fmt.Errorf("package %s not loaded", ref.Package)
	}
	obj := pkg.Types.Scope().Lookup(ref.Symbol)
	tn, ok := obj.(*types.TypeName)
	if !ok {
		return false, nil
	}
	named := mustNamed(tn)
	if named == nil {
		return false, nil
	}
	_, isStruct := named.Underlying().(*types.Struct)
	return isStruct, nil
}

// pkgByPath finds a loaded package by path, loading it on demand —
// dependency packages are not roots of the ./... load.
func (ix *Index) pkgByPath(ctx context.Context, pkgPath string) *packages.Package {
	for _, pkg := range ix.pkgs {
		if pkg.PkgPath == pkgPath && pkg.Types != nil {
			return pkg
		}
	}
	extra, err := ix.loadExtra(ctx, pkgPath)
	if err != nil {
		return nil
	}
	for _, pkg := range extra {
		if pkg.PkgPath == pkgPath && pkg.Types != nil {
			return pkg
		}
	}
	return nil
}
