package goanalysis

import (
	"go/ast"
	"go/types"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
	"golang.org/x/tools/go/packages"
)

// funcValueCallSites finds call sites that may invoke ref through a
// function value — `unmarshal(d, m)` where unmarshal is a map- or
// var-held function — sites a static callee scan cannot see. A site is
// counted when its resolved candidate set contains ref, or when the set
// is incomplete and the call's signature is compatible — both keep the
// caller enumeration conservative (a possible caller is a real writer
// candidate; an incompatible one is excluded).
func (ix *Index) funcValueCallSites(scope []*packages.Package, ref domain.SymbolRef, want *types.Signature) (sites []CallSiteRef) {
	key := ref.Package + "|" + strings.TrimPrefix(ref.Symbol, "*")
	// A method may be stored as a bound method value (receiver dropped)
	// or as a method expression (receiver becomes the first parameter) —
	// both signature shapes are partial-match compatible.
	var wantKeys []string
	if want != nil {
		wantKeys = append(wantKeys, fvSigKey(want))
		if recv := want.Recv(); recv != nil {
			params := make([]*types.Var, 0, want.Params().Len()+1)
			params = append(params, recv)
			for i := 0; i < want.Params().Len(); i++ {
				params = append(params, want.Params().At(i))
			}
			tup := types.NewTuple(params...)
			wantKeys = append(wantKeys, fvSigKey(types.NewSignatureType(nil, nil, nil, tup, want.Results(), want.Variadic())))
		}
	}
	for _, pkg := range scope {
		idx := ix.fvIndex(pkg)
		if idx == nil {
			continue
		}
		sites = append(sites, idx.byFunc[key]...)
		if idx.open {
			for _, p := range idx.pending {
				compatible := len(wantKeys) == 0
				for _, wk := range wantKeys {
					if fvSigKey(p.sig) == wk {
						compatible = true
						break
					}
				}
				if compatible {
					p.site.possible = true
					sites = append(sites, p.site)
				}
			}
			continue
		}
		for _, wk := range wantKeys {
			for _, s := range idx.partial[wk] {
				s.possible = true
				sites = append(sites, s)
			}
		}
	}
	return sites
}

// fvPkgIndex is a per-package index of function-value call sites: direct
// hits keyed by candidate symbol, plus signature-keyed sites whose
// candidate sets could not be closed (possible callers of any
// signature-compatible function). pending is the two-pass build's raw
// site list — kept on the index so func-valued parameters can include
// every same-package may-caller's argument while the index is building.
type fvPkgIndex struct {
	byFunc  map[string][]CallSiteRef
	partial map[string][]CallSiteRef
	pending []fvPendingSite
	open    bool
}

type fvPendingSite struct {
	site CallSiteRef
	sig  *types.Signature
}

// fvIndex builds (and caches) the func-value call index of pkg. The
// index survives extras growth — new packages index on demand — and is
// dropped with the extras generation so evicted ASTs are never reused.
// Build is two passes: every func-value call site is collected first, so
// candidate resolution in pass two sees the complete same-package set of
// may-callers regardless of visitation order.
func (ix *Index) fvIndex(pkg *packages.Package) *fvPkgIndex {
	if pkg == nil || pkg.TypesInfo == nil {
		return nil
	}
	gen := ix.extrasGen
	if ix.fvIdxGen != ix.extrasGen {
		ix.fvIdx = map[*packages.Package]*fvPkgIndex{}
		ix.fvIdxGen = ix.extrasGen
	}
	if idx, ok := ix.fvIdx[pkg]; ok {
		return idx
	}
	if ix.fvIdx == nil {
		ix.fvIdx = map[*packages.Package]*fvPkgIndex{}
	}
	idx := &fvPkgIndex{byFunc: map[string][]CallSiteRef{}, partial: map[string][]CallSiteRef{}}
	info := pkg.TypesInfo
	var enc *ast.FuncDecl
	for _, f := range pkg.Syntax {
		ast.Inspect(f, func(n ast.Node) bool {
			if fn, ok := n.(*ast.FuncDecl); ok {
				enc = fn
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			obj := calleeObject(info, call.Fun)
			// A direct named-function call is already enumerated by the
			// static scan — only variable/expr callees are new.
			if _, isFunc := obj.(*types.Func); isFunc {
				return true
			}
			ft := info.TypeOf(call.Fun)
			if ft == nil {
				return true
			}
			sig, _ := ft.Underlying().(*types.Signature)
			if sig == nil {
				return true
			}
			site := CallSiteRef{Site: ix.siteOf(pkg, enc, call), call: call, enclosing: enc, pkg: pkg}
			idx.pending = append(idx.pending, fvPendingSite{site, sig})
			return true
		})
	}
	ix.fvIdx[pkg] = idx // visible to nested lookups during pass two
	ix.fvBuildDepth++
	defer func() { ix.fvBuildDepth-- }()
	for _, p := range idx.pending {
		cands, partial := ix.funcCandidates(pkg, p.site.enclosing, p.site.call.Fun, map[ast.Expr]bool{}, 0)
		seen := map[string]bool{}
		for _, c := range cands {
			k := fvFuncKey(c)
			if k == "" || seen[k] {
				continue
			}
			seen[k] = true
			idx.byFunc[k] = append(idx.byFunc[k], p.site)
		}
		if partial {
			idx.partial[fvSigKey(p.sig)] = append(idx.partial[fvSigKey(p.sig)], p.site)
		}
	}
	if ix.extrasGen != gen {
		idx.open = true
		for k := range idx.byFunc {
			for i := range idx.byFunc[k] {
				idx.byFunc[k][i].possible = true
			}
		}
		for _, p := range idx.pending {
			p.site.possible = true
			idx.partial[fvSigKey(p.sig)] = append(idx.partial[fvSigKey(p.sig)], p.site)
		}
		if ix.fvIdxGen == gen && ix.fvIdx[pkg] == idx {
			delete(ix.fvIdx, pkg)
		}
	}
	return idx
}

// fvParamCallers enumerates the argument expressions that may supply a
// func-valued parameter (position idx) of enc: arguments at name-call
// and interface-dispatch sites, plus arguments at func-value call sites
// that may dispatch to enc (confirmed hits and signature-compatible
// may-callers, including the same-package sites pending resolution in
// the index being built). May-callers over-approximate the parameter's
// value set — extra candidates only widen dispatch, never hide it.
// open=true marks an under-counted caller set: invoked mid-build, the
// func-value indexes of scope packages not built yet are deferred rather
// than recursively constructed — package-graph fan-out would otherwise
// never terminate.
func (ix *Index) fvParamCallers(pkg *packages.Package, enc *ast.FuncDecl, idx int) (out []rhsAt, open bool) {
	ref := funcSymbolRef(pkg, enc)
	scope := ix.callerScope(pkg)
	seenCall := map[*ast.CallExpr]bool{}
	push := func(r CallSiteRef) {
		if r.call == nil || seenCall[r.call] || idx >= len(r.call.Args) {
			return
		}
		seenCall[r.call] = true
		out = append(out, rhsAt{r.pkg, r.enclosing, r.call.Args[idx]})
	}
	for _, r := range ix.findCallSitesIn(scope, ref) {
		push(r)
	}
	// Interface-dispatched callers: an `x.M(...)` call where x is an
	// interface enc implements — over-included (conservative).
	for _, iref := range ix.ifaceCallerRefs(ref) {
		for _, r := range ix.findCallSitesIn(scope, iref) {
			push(r)
		}
	}
	// Func-value callers: sites whose candidate set contains enc, or
	// whose set is unresolved and signature-compatible.
	var wantKeys []string
	refKey := ref.Package + "|" + strings.TrimPrefix(ref.Symbol, "*")
	if want := ix.funcSigOfRef(ref); want != nil {
		wantKeys = append(wantKeys, fvSigKey(want))
		if recv := want.Recv(); recv != nil {
			params := make([]*types.Var, 0, want.Params().Len()+1)
			params = append(params, recv)
			for i := 0; i < want.Params().Len(); i++ {
				params = append(params, want.Params().At(i))
			}
			wantKeys = append(wantKeys, fvSigKey(types.NewSignatureType(nil, nil, nil, types.NewTuple(params...), want.Results(), want.Variadic())))
		}
	}
	for _, p := range scope {
		i, indexed := ix.fvIdx[p]
		if !indexed {
			if ix.fvBuildDepth > 0 {
				// Mid-build: starting this package's index would recurse
				// through its own func-valued params back into packages
				// still under construction. Defer it and mark the caller
				// set under-counted — the candidate resolution above then
				// records the site as an unresolved may-caller.
				open = true
				continue
			}
			i = ix.fvIndex(p)
		}
		if i == nil {
			continue
		}
		open = open || i.open
		for _, s := range i.byFunc[refKey] {
			push(s)
		}
		for _, wk := range wantKeys {
			for _, s := range i.partial[wk] {
				push(s)
			}
			for _, ps := range i.pending {
				if fvSigKey(ps.sig) == wk {
					push(ps.site)
				}
			}
		}
	}
	return out, open
}

// fvFuncKey builds the lookup key matching ref.Package + "|" + ref.Symbol:
// plain functions key by name, methods by "Type.Name".
func fvFuncKey(fn *types.Func) string {
	if fn == nil || fn.Pkg() == nil {
		return ""
	}
	sym := fn.Name()
	if sig, ok := fn.Type().(*types.Signature); ok {
		if recv := sig.Recv(); recv != nil {
			t := recv.Type()
			if p, ok := t.(*types.Pointer); ok {
				t = p.Elem()
			}
			if named, ok := t.(*types.Named); ok && named.Obj() != nil {
				sym = named.Obj().Name() + "." + sym
			}
		}
	}
	return fn.Pkg().Path() + "|" + sym
}

// fvSigKey reduces a signature to its params+results identity — the
// dispatch shape a func-value call constrains candidates to.
func fvSigKey(sig *types.Signature) string {
	var b strings.Builder
	qual := func(p *types.Package) string { return p.Path() }
	b.WriteByte('(')
	for i := 0; i < sig.Params().Len(); i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(types.TypeString(sig.Params().At(i).Type(), qual))
	}
	b.WriteString(")->(")
	for i := 0; i < sig.Results().Len(); i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(types.TypeString(sig.Results().At(i).Type(), qual))
	}
	b.WriteByte(')')
	return b.String()
}

// funcCandidates resolves the set of functions a func-valued expression
// can dispatch to: static references, func-valued variables' writes,
// call results' return expressions, map/slice elements, struct fields
// and composite literals. open=true marks an unbounded tail — the
// candidate set is then an under-approximation.
func (ix *Index) funcCandidates(pkg *packages.Package, enc *ast.FuncDecl, expr ast.Expr, seen map[ast.Expr]bool, depth int) (funcs []*types.Func, open bool) {
	if expr == nil || depth > 8 || !ix.budgeted() {
		return nil, true
	}
	if seen[expr] {
		return nil, false
	}
	seen[expr] = true
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if e.Name == "nil" {
			return nil, false // nil writes contribute no functions
		}
		obj := pkg.TypesInfo.ObjectOf(e)
		switch o := obj.(type) {
		case *types.Func:
			return []*types.Func{o}, false
		case *types.Var:
			var out []*types.Func
			var anyOpen bool
			for _, rhs := range localAssigns(enc, o) {
				fs, op := ix.funcCandidates(pkg, enc, rhs, seen, depth+1)
				out = append(out, fs...)
				anyOpen = anyOpen || op
			}
			if enc != nil && isParam(enc, o) {
				// Func-valued parameter: every caller that may invoke the
				// enclosing function supplies a candidate implementation.
				if idx := paramIndexOf(enc, o.Name()); idx >= 0 && enc.Name != nil {
					args, underCounted := ix.fvParamCallers(pkg, enc, idx)
					anyOpen = anyOpen || underCounted
					for _, a := range args {
						fs, op := ix.funcCandidates(a.pkg, a.enc, a.expr, seen, depth+1)
						out = append(out, fs...)
						anyOpen = anyOpen || op
					}
				}
			}
			if len(out) == 0 {
				if vp := ix.pkgOfPath(o); vp != nil {
					if init := findVarInit(vp, o); init != nil {
						fs, op := ix.funcCandidates(vp, nil, init, seen, depth+1)
						out = append(out, fs...)
						anyOpen = anyOpen || op
					}
				}
			}
			if len(out) == 0 && !anyOpen {
				return nil, true
			}
			return out, anyOpen
		}
		return nil, true
	case *ast.CallExpr:
		fn, ok := calleeObject(pkg.TypesInfo, e.Fun).(*types.Func)
		if !ok || fn.Pkg() == nil {
			return nil, true
		}
		decl, dp := ix.funcDecl(fn)
		if decl == nil || decl.Body == nil || dp == nil {
			return nil, true
		}
		var out []*types.Func
		var anyOpen bool
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			rs, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, re := range rs.Results {
				fs, op := ix.funcCandidates(dp, decl, re, seen, depth+1)
				out = append(out, fs...)
				anyOpen = anyOpen || op
			}
			return true
		})
		return out, anyOpen
	case *ast.IndexExpr:
		// m[k] where m is a map var: candidates are the map's element
		// writes — initializers and m[k] = v assignments.
		if id, ok := ast.Unparen(e.X).(*ast.Ident); ok {
			if vr, ok2 := pkg.TypesInfo.ObjectOf(id).(*types.Var); ok2 {
				return ix.varFuncValues(pkg, vr, seen, depth+1)
			}
		}
		return nil, true
	case *ast.SelectorExpr:
		if sel, ok := pkg.TypesInfo.Selections[e]; ok {
			switch o := sel.Obj().(type) {
			case *types.Func:
				// Method value (`x.M`) or method expression (`T.M`) —
				// the selection object is the function itself.
				return []*types.Func{o}, false
			case *types.Var:
				if o.IsField() {
					var out []*types.Func
					var anyOpen bool
					for _, w := range ix.fieldWriteSites(o) {
						fs, op := ix.funcCandidates(w.pkg, w.enc, w.rhs, seen, depth+1)
						out = append(out, fs...)
						anyOpen = anyOpen || op
					}
					if len(out) == 0 && !anyOpen {
						return nil, true
					}
					return out, anyOpen
				}
			}
		}
		return nil, true
	case *ast.CompositeLit:
		var out []*types.Func
		var anyOpen bool
		for _, el := range e.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			fs, op := ix.funcCandidates(pkg, enc, el, seen, depth+1)
			out = append(out, fs...)
			anyOpen = anyOpen || op
		}
		return out, anyOpen
	}
	return nil, true
}

// varFuncValues collects function values ever written into a variable:
// its initializer and element writes (`m[k] = f`) visible to the index.
// The resolved set is cached per variable — element-write scans over
// the dep set are the hot path of func-value resolution. inFlight cuts
// recursive var→var resolution; a cycle reports open (under-approximate
// rather than loop).
func (ix *Index) varFuncValues(pkg *packages.Package, vr *types.Var, seen map[ast.Expr]bool, depth int) (funcs []*types.Func, open bool) {
	if c, ok := ix.funcValsCache[vr]; ok && c.gen == ix.extrasGen {
		return c.funcs, c.open
	}
	if ix.funcValsIn == nil {
		ix.funcValsIn = map[*types.Var]bool{}
	}
	if ix.funcValsIn[vr] {
		return nil, true
	}
	ix.funcValsIn[vr] = true
	defer delete(ix.funcValsIn, vr)
	vp := ix.pkgOfPath(vr)
	if vp == nil {
		return nil, true
	}
	gen := ix.extrasGen
	var out []*types.Func
	var anyOpen bool
	eval := func(p *packages.Package, expr ast.Expr) {
		// Fresh seen per write expression: the cached result must not
		// depend on the caller's in-flight visited set.
		fs, op := ix.funcCandidates(p, nil, expr, map[ast.Expr]bool{}, depth+1)
		out = append(out, fs...)
		anyOpen = anyOpen || op
	}
	if init := findVarInit(vp, vr); init != nil {
		eval(vp, init)
	}
	for _, w := range ix.varElemWrites(vr) {
		eval(w.pkg, w.expr)
	}
	open = len(out) == 0 || anyOpen
	if ix.extrasGen != gen {
		open = true
		return out, open
	}
	if ix.funcValsCache == nil {
		ix.funcValsCache = map[*types.Var]funcValEntry{}
	}
	ix.funcValsCache[vr] = funcValEntry{gen: gen, funcs: out, open: open}
	return out, open
}

// funcValEntry caches a func-valued variable's resolved candidate set;
// gen tracks extrasGen so ASTs evicted with extras are never reused.
type funcValEntry struct {
	gen   int
	funcs []*types.Func
	open  bool
}

// varElemWrites finds `v[k] = x` index-assignments of a variable across
// the loaded scope — the map-element counterpart of fieldWriteSites.
// Product roots are included: product-side registrations
// (`registry["s3"] = myGetter`) feed dep dispatch the same as dep ones.
func (ix *Index) varElemWrites(vr *types.Var) []rhsAt {
	var out []rhsAt
	for _, pkg := range append(ix.allExtras(), ix.pkgs...) {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		var enc *ast.FuncDecl
		for _, f := range pkg.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enc = fn
				}
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for i, lhs := range as.Lhs {
					ie, ok := ast.Unparen(lhs).(*ast.IndexExpr)
					if !ok || i >= len(as.Rhs) {
						continue
					}
					if id, ok := ast.Unparen(ie.X).(*ast.Ident); ok {
						if info.ObjectOf(id) == types.Object(vr) {
							out = append(out, rhsAt{pkg, enc, as.Rhs[i]})
						}
					}
				}
				return true
			})
		}
	}
	return out
}

// funcSigOfRef resolves the declared signature of the symbol a
// func-value call would dispatch to. Method signatures keep their
// receiver — funcValueCallSites derives both stored-value shapes (bound
// method value and method expression) from it.
func (ix *Index) funcSigOfRef(ref domain.SymbolRef) *types.Signature {
	typeName, name := splitSymbol(ref.Symbol)
	var pkgs []*packages.Package
	pkgs = append(pkgs, ix.pkgs...)
	pkgs = append(pkgs, ix.allExtras()...)
	for _, p := range pkgs {
		if p.PkgPath != ref.Package || p.Types == nil {
			continue
		}
		if typeName == "" {
			if fn, ok := p.Types.Scope().Lookup(name).(*types.Func); ok {
				if sig, ok2 := fn.Type().(*types.Signature); ok2 {
					return sig
				}
			}
			continue
		}
		tn, _ := p.Types.Scope().Lookup(typeName).(*types.TypeName)
		if tn == nil {
			continue
		}
		named, _ := tn.Type().(*types.Named)
		if named == nil {
			continue
		}
		for i := 0; i < named.NumMethods(); i++ {
			m := named.Method(i)
			if m.Name() != name {
				continue
			}
			if sig, ok := m.Type().(*types.Signature); ok {
				return sig
			}
		}
	}
	return nil
}

// pkgOfPath locates the loaded package a package-level var belongs to —
// product roots first, then dep packages loaded on demand.
func (ix *Index) pkgOfPath(vr *types.Var) *packages.Package {
	if vr == nil || vr.Pkg() == nil {
		return nil
	}
	for _, p := range ix.pkgs {
		if p.PkgPath == vr.Pkg().Path() {
			return p
		}
	}
	for _, extras := range ix.extraPkgs {
		for _, p := range extras {
			if p.PkgPath == vr.Pkg().Path() {
				return p
			}
		}
	}
	if extra, err := ix.loadExtra(ix.ctxOr(nil), vr.Pkg().Path()); err == nil {
		for _, p := range extra {
			if p.PkgPath == vr.Pkg().Path() {
				return p
			}
		}
	}
	return nil
}
