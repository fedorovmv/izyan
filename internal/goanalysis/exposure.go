package goanalysis

import (
	"context"
	"go/ast"
	"go/constant"
	"go/types"
	"golang.org/x/tools/go/packages"
	"regexp"
	"strconv"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// listenAddrArg indexes the address argument per listener primitive, or
// -1 when the address lives outside the call (http.Server.Addr field,
// grpc Server.Serve(listener)).
var listenAddrArg = map[string]int{
	"net.Listen":                              1,
	"net.ListenTCP":                           1,
	"net.ListenUDP":                           1,
	"net/http.ListenAndServe":                 0,
	"net/http.ListenAndServeTLS":              0,
	"net/http.Server.ListenAndServe":          -1,
	"net/http.Server.Serve":                   -1,
	"google.golang.org/grpc.NewServer":        -1,
	"google.golang.org/grpc.Server.Serve":     -1,
	"google.golang.org/grpc.Server.ServeHTTP": -1,
	"net.Listener.Accept":                     -1,
}

// dialNameRe matches API names that initiate outbound connections:
// Dial*/DialContext/Connect/Open/NewClient-style callees inside the
// vulnerable module.
var dialNameRe = regexp.MustCompile(`(?i)dial|^connect$|^open$|^newclient$`)

// ListenSites reports every product call site of a listener primitive —
// one fact per call, with the bound address resolved through literals,
// constants, simple var initializers, os.Getenv and struct fields.
// Server-shape calls (Server.Serve, Serve(lis)) resolve the address by
// tracing the receiver/listener expression inside the enclosing function.
func (ix *Index) ListenSites(ctx context.Context) ([]domain.ExposureFact, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.ExposureFact
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					for _, prim := range listenerPrimitives {
						key := prim.Package + "." + prim.Symbol
						if !callIsSymbol(info, call.Fun, prim) {
							continue
						}
						fact := domain.ExposureFact{
							Direction: "inbound",
							Kind:      "listener",
							Target:    key,
							CallSite:  ix.callSiteAt(pkg, fn, call),
						}
						ix.resolveListenAddr(info, pkg, fn, call, key, &fact)
						out = append(out, fact)
					}
					return true
				})
			}
		}
	}
	return out, nil
}

// DialSites reports product call sites that initiate outbound connections
// into the given module — for client-side vulnerabilities the exposure
// question is where the product connects. The endpoint argument is
// resolved like listener addresses.
func (ix *Index) DialSites(ctx context.Context, module string) ([]domain.ExposureFact, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.ExposureFact
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					callee, ok := calleeObject(info, call.Fun).(*types.Func)
					if !ok || callee.Pkg() == nil ||
						!strings.HasPrefix(callee.Pkg().Path(), module) ||
						!dialNameRe.MatchString(callee.Name()) {
						return true
					}
					fact := domain.ExposureFact{
						Direction: "outbound",
						Kind:      "dial",
						Target:    callee.Pkg().Path() + "." + callee.Name(),
						CallSite:  ix.callSiteAt(pkg, fn, call),
					}
					ix.resolveDialAddr(info, pkg, fn, call, &fact)
					out = append(out, fact)
					return true
				})
			}
		}
	}
	return out, nil
}

// authNameRe matches middleware/interceptor names that plausibly carry
// an authentication or authorization check. It is only applied in
// middleware positions (Use/With args, grpc interceptor options, the
// handler argument of an http listener) — never to arbitrary calls.
var authNameRe = regexp.MustCompile(`(?i)(auth|jwt|oauth|token|authoriz|rbac|permission|session|login|verify)`)

// InboundAuthFacts reports authentication-middleware wiring observed in
// functions that also contain a listener primitive or grpc.NewServer —
// "this server is wired behind an auth check". Facts are deployment
// hints, not request-level proof: a middleware named authX in the same
// function suggests inbound requests are filtered, but which routes are
// covered is beyond this static pass.
func (ix *Index) InboundAuthFacts(ctx context.Context) ([]domain.ExposureFact, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	var out []domain.ExposureFact
	for _, pkg := range ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			if ix.isTestFile(f) {
				continue
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if !fnWiresServer(info, fn.Body) {
					continue
				}
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					name, ok := middlewareAuthName(info, call)
					if !ok {
						return true
					}
					out = append(out, domain.ExposureFact{
						Direction: "inbound",
						Kind:      "auth-middleware",
						Target:    name,
						CallSite:  ix.callSiteAt(pkg, fn, call),
					})
					return true
				})
			}
		}
	}
	return out, nil
}

// fnWiresServer reports whether the function body contains a listener
// primitive or constructs a server (grpc.NewServer).
func fnWiresServer(info *types.Info, body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, prim := range listenerPrimitives {
			if callIsSymbol(info, call.Fun, prim) {
				found = true
				return false
			}
		}
		if callIsSymbol(info, call.Fun, domain.SymbolRef{
			Package: "google.golang.org/grpc", Symbol: "NewServer"}) {
			found = true
			return false
		}
		return true
	})
	return found
}

// middlewareAuthName recognizes auth-marked names in middleware
// positions: r.Use(mw)/r.With(mw) args, grpc interceptor options and
// wrapped handlers passed to listeners. Returns the matched name.
func middlewareAuthName(info *types.Info, call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	method := sel.Sel.Name
	// r.Use(authMw) / r.With(authMw): middleware arg name.
	if method == "Use" || method == "With" {
		for _, a := range call.Args {
			if n := exprName(info, a); authNameRe.MatchString(n) {
				return method + ":" + n, true
			}
		}
		return "", false
	}
	// grpc.NewServer(grpc.UnaryInterceptor(authFn)) — the option callee
	// is the interceptor constructor; its argument is the middleware.
	if method == "UnaryInterceptor" || method == "StreamInterceptor" {
		for _, a := range call.Args {
			if n := exprName(info, a); authNameRe.MatchString(n) {
				return "grpc." + method + ":" + n, true
			}
		}
		return "", false
	}
	// http.ListenAndServe(addr, authWrap(h)) — wrapped handler arg.
	for _, prim := range listenerPrimitives {
		if !callIsSymbol(info, call.Fun, prim) {
			continue
		}
		for _, a := range call.Args {
			if wc, ok := a.(*ast.CallExpr); ok {
				if n := exprName(info, wc.Fun); authNameRe.MatchString(n) {
					return "handler-wrap:" + n, true
				}
			}
		}
	}
	return "", false
}

// exprName yields the bare callable/identifier name for an expression —
// identifier, selector, or the callee of a call expression.
func exprName(info *types.Info, e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.CallExpr:
		return exprName(info, x.Fun)
	}
	return ""
}

// resolveListenAddr fills fact.Address/AddressSource for a listener call.
func (ix *Index) resolveListenAddr(info *types.Info, pkg *packages.Package, fn *ast.FuncDecl, call *ast.CallExpr, key string, fact *domain.ExposureFact) {
	idx, known := listenAddrArg[key]
	if known && idx >= 0 && idx < len(call.Args) {
		fact.Address, fact.AddressSource = ix.exprStringValue(info, pkg, fn, call.Args[idx])
		return
	}
	// Server-shape: trace the receiver/listener expression back to its
	// defining call or composite literal within the same function.
	recv := call.Fun
	if sel, ok := recv.(*ast.SelectorExpr); ok {
		recv = sel.X
	}
	fact.Address, fact.AddressSource = ix.traceAddr(info, pkg, fn, recv)
}

// traceAddr resolves an expression expected to hold a listener/server:
// composite literals (http.Server{Addr:…}) and idents assigned from a
// listener call or literal in the enclosing function.
func (ix *Index) traceAddr(info *types.Info, pkg *packages.Package, fn *ast.FuncDecl, e ast.Expr) (string, string) {
	switch x := e.(type) {
	case *ast.UnaryExpr:
		if lit, ok := x.X.(*ast.CompositeLit); ok {
			return compositeAddr(info, lit)
		}
	case *ast.CompositeLit:
		return compositeAddr(info, x)
	case *ast.Ident:
		return ix.identAssignedAddr(info, pkg, fn, x)
	}
	return "", ""
}

// identAssignedAddr scans the enclosing function for `x := net.Listen(
// "tcp", addr)` / `x := &http.Server{Addr: addr}` / `x := "addr"`.
func (ix *Index) identAssignedAddr(info *types.Info, pkg *packages.Package, fn *ast.FuncDecl, id *ast.Ident) (string, string) {
	var val, src string
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if val != "" {
			return false
		}
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		ass := false
		for _, lhs := range as.Lhs {
			if li, ok := lhs.(*ast.Ident); ok && li.Name == id.Name {
				ass = true
			}
		}
		if !ass || len(as.Rhs) == 0 {
			return true
		}
		switch r := as.Rhs[0].(type) {
		case *ast.CallExpr:
			// listener primitive? resolve its addr arg
			for _, prim := range listenerPrimitives {
				key := prim.Package + "." + prim.Symbol
				if callIsSymbol(info, r.Fun, prim) {
					if idx := listenAddrArg[key]; idx >= 0 && idx < len(r.Args) {
						val, src = ix.exprStringValue(info, pkg, fn, r.Args[idx])
					}
				}
			}
		case *ast.UnaryExpr:
			if lit, ok := r.X.(*ast.CompositeLit); ok {
				val, src = compositeAddr(info, lit)
			}
		case *ast.CompositeLit:
			val, src = compositeAddr(info, r)
		default:
			val, src = ix.exprStringValue(info, pkg, fn, as.Rhs[0])
		}
		return true
	})
	return val, src
}

// compositeAddr extracts the Addr/address field from a composite literal
// like &http.Server{Addr: ":9090"}.
func compositeAddr(info *types.Info, lit *ast.CompositeLit) (string, string) {
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		if strings.EqualFold(key.Name, "Addr") || strings.EqualFold(key.Name, "Address") ||
			strings.EqualFold(key.Name, "ListenAddr") {
			return exprString(info, kv.Value)
		}
	}
	return "", ""
}

// exprStringValue resolves an expression expected to yield the address:
// one-hop var resolution inside the enclosing function is included.
func (ix *Index) exprStringValue(info *types.Info, pkg *packages.Package, fn *ast.FuncDecl, e ast.Expr) (string, string) {
	if id, ok := e.(*ast.Ident); ok {
		if _, isVar := info.ObjectOf(id).(*types.Var); isVar {
			if v, s := ix.identAssignedAddr(info, pkg, fn, id); v != "" || s != "" {
				return v, s
			}
		}
	}
	return exprString(info, e)
}

// exprString is the leaf resolver: literals, constants, os.Getenv,
// package-level vars and field accesses.
func exprString(info *types.Info, e ast.Expr) (string, string) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if s, err := strconv.Unquote(x.Value); err == nil {
			return s, "literal"
		}
	case *ast.Ident:
		switch obj := info.ObjectOf(x).(type) {
		case *types.Const:
			if v := obj.Val(); v != nil && v.Kind() == constant.String {
				return constant.StringVal(v), "const"
			}
		case *types.Var:
			// Package-level var initializers are not resolved here —
			// the ident path through identAssignedAddr covers locals;
			// package vars stay unresolved (recorded, not guessed).
			return "", "var:" + obj.Name()
		}
	case *ast.CallExpr:
		if fn, ok := calleeObject(info, x.Fun).(*types.Func); ok && fn.Pkg() != nil &&
			fn.Pkg().Path() == "os" && (fn.Name() == "Getenv" || fn.Name() == "LookupEnv") &&
			len(x.Args) > 0 {
			if name, ok := literalString(x.Args[0]); ok {
				return "", "env:" + name
			}
		}
	case *ast.SelectorExpr:
		if seln, ok := info.Selections[x]; ok {
			return "", "field:" + recvTypeName(seln.Recv()) + "." + seln.Obj().Name()
		}
		if id, ok := x.X.(*ast.Ident); ok {
			return "", "field:" + id.Name + "." + x.Sel.Name
		}
	}
	return "", ""
}

// resolveDialAddr picks the address-ish argument of an outbound call:
// the first arg resolving to something that looks like an address/URL,
// else the first arg.
func (ix *Index) resolveDialAddr(info *types.Info, pkg *packages.Package, fn *ast.FuncDecl, call *ast.CallExpr, fact *domain.ExposureFact) {
	for i, a := range call.Args {
		val, src := ix.exprStringValue(info, pkg, fn, a)
		if src == "" && val == "" {
			continue
		}
		if i == 0 || addrish(val) || strings.HasPrefix(src, "env:") || strings.HasPrefix(src, "config:") {
			fact.Address, fact.AddressSource = val, src
			return
		}
	}
	if len(call.Args) > 0 {
		fact.Address, fact.AddressSource = ix.exprStringValue(info, pkg, fn, call.Args[0])
	}
}

var addrishRe = regexp.MustCompile(`(?i)(://|\.sock\b|^unix|^\d+\.\d+\.\d+\.\d+|localhost|:\d)`)

func addrish(v string) bool { return addrishRe.MatchString(v) }

func literalString(e ast.Expr) (string, bool) {
	if lit, ok := e.(*ast.BasicLit); ok {
		s, err := strconv.Unquote(lit.Value)
		return s, err == nil
	}
	return "", false
}

// isTestFile filters out test sources: test code is not deployed attack
// surface, so listeners/dials there are noise for exposure facts.
func (ix *Index) isTestFile(f *ast.File) bool {
	return strings.HasSuffix(ix.fset.Position(f.Pos()).Filename, "_test.go")
}

// callSiteAt builds a CallSite for a call expression inside fn.
func (ix *Index) callSiteAt(pkg *packages.Package, fn *ast.FuncDecl, call *ast.CallExpr) domain.CallSite {
	pos := ix.fset.Position(call.Pos())
	cs := domain.CallSite{
		File:    pos.Filename,
		Line:    pos.Line,
		Package: pkg.PkgPath,
	}
	if fn != nil && fn.Name != nil {
		cs.Function = fn.Name.Name
	}
	if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
		cs.Callee = sel.Sel.Name
	}
	return cs
}
