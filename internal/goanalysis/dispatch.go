package goanalysis

import (
	"go/ast"
	"go/constant"
	"go/types"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"
)

// dispatch.go — per-callsite interface dispatch narrowing.
//
// An interface call `recv.M(...)` can dispatch only to the concrete types
// `recv` may hold. When `recv` comes from a map/lookup on a literal
// registry (`g := getters[key]`) and `key` evaluates to constants, the
// impl set is the literal's values at those keys — a falsifier-grade
// narrowing (e.g. `force="https"` → only HttpGetter, never GitGetter).
// Any unresolvable step widens back to all impls: narrowing is used to
// *remove* impossible targets, never to fabricate absence — when the key
// or the table cannot be evaluated the site stays unrestricted.

// maxDispatchFuel bounds the string-value evaluator — it is a bounded
// interprocedural fold, not a general interpreter. Depth covers long
// dep-internal chains (registry key ← field write ← caller arg ←
// split/query transform) without making cycles possible — the seen set
// already cuts those.
const (
	maxDispatchFuel  = 128
	maxDispatchDepth = 24
)

// rhsOf pairs an assignment RHS with how it binds: ordinary `x = e` and
// parallel `a, b := e1, e2` give (eN, 0, false); a multi-result call
// `a, b := f()` gives (call, N, true) so semantic evaluators pick the
// right return slot.
type rhsOf struct {
	expr  ast.Expr
	idx   int
	multi bool
}

// assignRHS returns RHS expressions assigned to obj inside enc, including
// var-spec initializers. Multi-result calls report their LHS position so
// semantic evaluators pick the right return slot.
func assignRHS(info *types.Info, enc *ast.FuncDecl, obj types.Object) []rhsOf {
	var out []rhsOf
	if enc == nil || enc.Body == nil || info == nil || obj == nil {
		return out
	}
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		switch a := n.(type) {
		case *ast.AssignStmt:
			for i, l := range a.Lhs {
				lid, ok := l.(*ast.Ident)
				if !ok || info.ObjectOf(lid) != obj {
					continue
				}
				switch {
				case i < len(a.Rhs):
					out = append(out, rhsOf{a.Rhs[i], 0, false})
				case len(a.Rhs) == 1:
					out = append(out, rhsOf{a.Rhs[0], i, true})
				}
			}
		case *ast.ValueSpec:
			for i, name := range a.Names {
				if info.ObjectOf(name) != obj || i >= len(a.Values) {
					continue
				}
				out = append(out, rhsOf{a.Values[i], 0, false})
			}
		}
		return true
	})
	return out
}

// dispatchImpls returns the set of concrete impl type names the callsite
// may dispatch to, or nil when unrestricted. The enclosing function is
// known, so receiver assignments resolve locally.
func (ix *Index) dispatchImpls(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr) map[string]bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || pkg.TypesInfo == nil || enc == nil {
		return nil
	}
	// Receiver must resolve to map-indexed value(s): `m[k].M()` directly,
	// or `g := m[k]` bindings. Every assignment to the receiver var is a
	// candidate binding — keeping only the last one would drop impls a
	// reassignment can still produce (`r := m[a]; if f { r = m[b] }`).
	var pairs [][2]ast.Expr
	if idx, ok := sel.X.(*ast.IndexExpr); ok {
		pairs = append(pairs, [2]ast.Expr{idx.X, idx.Index})
	} else if id, ok := sel.X.(*ast.Ident); ok {
		obj := pkg.TypesInfo.ObjectOf(id)
		rhs := assignRHS(pkg.TypesInfo, enc, obj)
		if len(rhs) == 0 {
			return nil
		}
		for _, r := range rhs {
			ie, ok := r.expr.(*ast.IndexExpr)
			if !ok {
				return nil // bound to a non-lookup — unrestricted
			}
			pairs = append(pairs, [2]ast.Expr{ie.X, ie.Index})
		}
	} else {
		return nil
	}
	impls := map[string]bool{}
	for _, p := range pairs {
		table, ok := ix.mapTable(pkg, enc, p[0])
		if !ok {
			return nil
		}
		vals, complete := ix.stringVals(pkg, enc, p[1], maxDispatchFuel)
		if !complete || len(vals) == 0 {
			return nil
		}
		for k := range vals {
			for name := range table[k] {
				impls[name] = true
			}
		}
	}
	return impls
}

// mapTable resolves a map operand to key-string → impl type names. The
// table is complete only when every write feeding the map resolves to a
// composite literal or a var whose initializer is one — an unresolved
// write means entries we cannot see, so no narrowing is sound.
func (ix *Index) mapTable(pkg *packages.Package, enc *ast.FuncDecl, mapExpr ast.Expr) (map[string]map[string]bool, bool) {
	lits := ix.mapLiterals(pkg, enc, mapExpr, 0)
	if len(lits) == 0 {
		return nil, false
	}
	table := map[string]map[string]bool{}
	complete := true
	for _, lit := range lits {
		litPkg := ix.pkgOfFile(lit)
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				return nil, false // positional elements — keys unknown
			}
			info := pkg.TypesInfo
			if litPkg != nil {
				info = litPkg.TypesInfo
			}
			keys, okc := ix.stringVals(pkg, enc, kv.Key, 8)
			if !okc {
				return nil, false
			}
			for k := range keys {
				if table[k] == nil {
					table[k] = map[string]bool{}
				}
				if tn := namedTypeName(info.TypeOf(kv.Value)); tn != "" {
					table[k][tn] = true
				}
			}
		}
	}
	return table, complete
}

// exprIsAnyVar reports whether e names a tracked object — an object in
// the alias set — directly (`m`), through a field selector (`c.M`), a
// pointer dereference, or address-taken (`&m`). The set is keyed by
// types.Object.Id so a dep var loaded in a separate packages.Load still
// matches product-side references to it.
func exprIsAnyVar(info *types.Info, e ast.Expr, set map[string]bool) bool {
	switch ex := e.(type) {
	case *ast.Ident:
		if o := info.ObjectOf(ex); o != nil {
			return set[o.Id()]
		}
	case *ast.SelectorExpr:
		if o := info.ObjectOf(ex.Sel); o != nil {
			return set[o.Id()]
		}
	case *ast.UnaryExpr:
		return exprIsAnyVar(info, ex.X, set)
	case *ast.ParenExpr:
		return exprIsAnyVar(info, ex.X, set)
	}
	return false
}

// mapAliases collects every object bound to the map value in pkg:
// `a := m` and `var a = m` share the table, so writes through aliases
// are writes to it. Binding the map to a non-variable target (a struct
// field, a slice slot, a pointer write) hands it to code whose writes
// this scan cannot see — reported as escape. Keys are Object.Id, not
// pointers: the same package-level var resolves to different objects in
// product vs dependency loads.
func mapAliases(info *types.Info, pkg *packages.Package, v types.Object) (set map[string]bool, escaped bool) {
	set = map[string]bool{v.Id(): true}
	for changed := true; changed && !escaped; {
		changed = false
		for _, f := range pkg.Syntax {
			if escaped {
				break
			}
			ast.Inspect(f, func(n ast.Node) bool {
				if escaped {
					return false
				}
				var lhs []ast.Expr
				var rhs []ast.Expr
				switch node := n.(type) {
				case *ast.AssignStmt:
					lhs, rhs = node.Lhs, node.Rhs
				case *ast.ValueSpec:
					lhs, rhs = nil, node.Values
					for _, nm := range node.Names {
						lhs = append(lhs, nm)
					}
				default:
					return true
				}
				// Multi-valued RHS (f(), m[k]) collapses positions —
				// only 1:1 pairs are alias binds.
				if len(lhs) != len(rhs) {
					for _, r := range rhs {
						if exprIsAnyVar(info, r, set) {
							escaped = true
						}
					}
					return true
				}
				for i, r := range rhs {
					if !exprIsAnyVar(info, r, set) {
						continue
					}
					if lid, ok := lhs[i].(*ast.Ident); ok && lid.Name != "_" {
						if o := info.ObjectOf(lid); o != nil && !set[o.Id()] {
							set[o.Id()] = true
							changed = true
						}
						continue
					}
					escaped = true // map bound into a field/slot/deref
				}
				return true
			})
		}
	}
	return set, escaped
}

// mapMutated reports whether the resolved map variable is written or
// escapes anywhere the analyzer cannot read. `m[k] = v` adds entries the
// literal never declared, `delete`/callee writes/remove equally break
// the table's completeness, and passing the map to a non-builtin call,
// a channel or a return hands it to code whose writes are invisible to
// this scan — the same holds for every alias (`a := m; a[k] = v`).
// A mutated map's literal content is not the full table — dispatch
// narrowing on it would drop reachable implementations.
func (ix *Index) mapMutated(v types.Object) bool {
	if v == nil {
		return true
	}
	for _, pkg := range append(ix.allExtras(), ix.pkgs...) {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		aliases, escaped := mapAliases(info, pkg, v)
		if escaped {
			return true
		}
		mut := false
		for _, f := range pkg.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				if mut {
					return false
				}
				switch node := n.(type) {
				case *ast.AssignStmt:
					for _, l := range node.Lhs {
						if idx, ok := l.(*ast.IndexExpr); ok && exprIsAnyVar(info, idx.X, aliases) {
							mut = true
						}
					}
				case *ast.SendStmt:
					if exprIsAnyVar(info, node.Value, aliases) {
						mut = true
					}
				case *ast.CompositeLit:
					// The map embedded in an aggregate literal escapes:
					// writes through the field/slot are invisible here.
					for _, e := range node.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							e = kv.Value
						}
						if exprIsAnyVar(info, e, aliases) {
							mut = true
						}
					}
				case *ast.ReturnStmt:
					for _, r := range node.Results {
						if exprIsAnyVar(info, r, aliases) {
							mut = true
						}
					}
				case *ast.CallExpr:
					if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "delete" && len(node.Args) > 0 {
						if exprIsAnyVar(info, node.Args[0], aliases) {
							mut = true
						}
						break
					}
					if _, builtin := calleeObject(info, node.Fun).(*types.Builtin); builtin {
						break
					}
					for _, a := range node.Args {
						if exprIsAnyVar(info, a, aliases) {
							mut = true
						}
					}
				}
				return true
			})
			if mut {
				return true
			}
		}
	}
	return false
}

// mapLiterals resolves mapExpr to its initializing composite literals:
// ident → assigns/var-spec → CompositeLit; field selector → cone-scoped
// field writes → recurse on each RHS. nil means the map's contents are
// unknowable (external source, product-supplied, index-mutated).
func (ix *Index) mapLiterals(pkg *packages.Package, enc *ast.FuncDecl, e ast.Expr, depth int) []*ast.CompositeLit {
	return ix.mapLiteralsRec(pkg, enc, e, depth, map[types.Object]bool{})
}

func (ix *Index) mapLiteralsRec(pkg *packages.Package, enc *ast.FuncDecl, e ast.Expr, depth int, seen map[types.Object]bool) []*ast.CompositeLit {
	if depth > 4 || pkg.TypesInfo == nil {
		return nil
	}
	switch ex := e.(type) {
	case *ast.CompositeLit:
		return []*ast.CompositeLit{ex}
	case *ast.Ident:
		obj := pkg.TypesInfo.ObjectOf(ex)
		v, ok := obj.(*types.Var)
		if !ok || seen[obj] {
			return nil
		}
		if ix.mapMutated(v) {
			// Entries may be added/removed where the scan cannot see —
			// the literal set is not the complete table.
			return nil
		}
		seen[obj] = true
		defer delete(seen, obj)
		var out []*ast.CompositeLit
		// Parameter: literals arrive from callers' args. No on-path
		// caller at all means the write is dead within the loaded
		// scope — it contributes nothing rather than poisoning the
		// table; a caller whose arg won't evaluate still fails closed.
		if enc != nil {
			if idx := paramIndexOf(enc, v.Name()); idx >= 0 {
				seenAny := false
				for _, r := range ix.callersOf(pkg, funcSymbolRef(pkg, enc)) {
					if r.possible {
						return nil
					}
					if idx >= len(r.call.Args) || !ix.callerOnPath(r) {
						continue
					}
					seenAny = true
					sub := ix.mapLiteralsRec(r.pkg, r.enclosing, r.call.Args[idx], depth+1, seen)
					if sub == nil {
						return nil
					}
					out = append(out, sub...)
				}
				if seenAny {
					return out
				}
			}
		}
		for _, r := range assignRHS(pkg.TypesInfo, enc, v) {
			sub := ix.mapLiteralsRec(pkg, enc, r.expr, depth+1, seen)
			if sub == nil {
				return nil
			}
			out = append(out, sub...)
		}
		if len(out) > 0 {
			return out
		}
		if enc != nil && paramIndexOf(enc, v.Name()) >= 0 {
			return []*ast.CompositeLit{}
		}
		// Package-level var: `var Getters map[string]Getter` + literal
		// assignment (possibly inside init).
		return ix.pkgVarLiterals(v)
	case *ast.SelectorExpr:
		// Field read like `c.Getters`: instance-sensitive — map literals
		// arrive via `T{F: lit}` initializers of the instances `x` may
		// hold, and via `b.F = v` writes whose base overlaps `x`'s
		// instances. A self-propagating write (`Getters: c.Getters`)
		// re-enters the same field — its literals are already being
		// collected by the outer visit, the fixpoint contributes nothing.
		fv, ok := pkg.TypesInfo.ObjectOf(ex.Sel).(*types.Var)
		if !ok {
			return nil
		}
		if seen[fv] {
			return []*ast.CompositeLit{}
		}
		if ix.mapMutated(fv) {
			return nil
		}
		seen[fv] = true
		defer delete(seen, fv)
		exprs, ok := ix.fieldValueExprs(pkg, enc, ex, depth, seen)
		if !ok {
			return nil
		}
		var out []*ast.CompositeLit
		for _, fe := range exprs {
			sub := ix.mapLiteralsRec(fe.pkg, fe.enc, fe.expr, depth+1, seen)
			if sub == nil {
				return nil
			}
			out = append(out, sub...)
		}
		return out
	}
	return nil
}

// fvExpr is a field's producing expression resolved in its own package
// and enclosing function (literal initializers and assignments may live
// in different frames).
type fvExpr struct {
	pkg  *packages.Package
	enc  *ast.FuncDecl
	expr ast.Expr
}

// fieldValueExprs resolves a field read `x.F` to the expressions that
// produce its values — instance-sensitive:
//
//   - `T{F: e}` initializers of every instance `x` may hold (receiver
//     params resolved through on-path callers' receiver expressions);
//   - `b.F = e` statement writes where b's instance set overlaps x's —
//     an unresolvable base keeps the write (fail closed), a provably
//     disjoint base is dropped (other Clients' Src writes cannot reach
//     the product's Client).
//
// complete=false means a producer could not be resolved — the caller
// must widen rather than trust the partial set.
func (ix *Index) fieldValueExprs(pkg *packages.Package, enc *ast.FuncDecl, sel *ast.SelectorExpr, depth int, seen map[types.Object]bool) ([]fvExpr, bool) {
	info := pkg.TypesInfo
	if info == nil || depth > maxDispatchDepth {
		return nil, false
	}
	fv, ok := info.ObjectOf(sel.Sel).(*types.Var)
	if !ok {
		return nil, false
	}
	lits, complete := ix.instSrcs(pkg, enc, sel.X, depth, seen)
	if !complete {
		return nil, false
	}
	var out []fvExpr
	for _, si := range lits {
		if si.pkg.TypesInfo == nil {
			return nil, false
		}
		for _, elt := range si.lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			kid, ok := kv.Key.(*ast.Ident)
			if !ok || si.pkg.TypesInfo.ObjectOf(kid) != fv {
				continue
			}
			out = append(out, fvExpr{si.pkg, si.enc, kv.Value})
		}
	}
	// Statement writes `b.F = v`: keep writes whose base instances
	// overlap x's, drop provably disjoint ones, fail closed on the rest.
	litSet := map[*ast.CompositeLit]bool{}
	for _, si := range lits {
		litSet[si.lit] = true
	}
	for _, w := range ix.fieldWriteSites(fv) {
		if !ix.siteOnPath(w.pkg, w.enc) || w.base == nil {
			continue
		}
		blits, bc := ix.instSrcs(w.pkg, w.enc, w.base, depth+1, map[types.Object]bool{})
		overlap := !bc // unresolvable base — write may hit our instance
		for _, bi := range blits {
			if litSet[bi.lit] {
				overlap = true
			}
		}
		if overlap {
			out = append(out, fvExpr{w.pkg, w.enc, w.rhs})
		}
	}
	return out, true
}

// recvVar reports whether v is the method receiver parameter of enc.
func recvVar(enc *ast.FuncDecl, v *types.Var) bool {
	if enc == nil || enc.Recv == nil || len(enc.Recv.List) == 0 {
		return false
	}
	for _, n := range enc.Recv.List[0].Names {
		if n.Name == v.Name() {
			return true
		}
	}
	return false
}

// srcInst is a composite literal resolved as an instance source,
// tagged with the frame it physically lives in.
type srcInst struct {
	lit *ast.CompositeLit
	pkg *packages.Package
	enc *ast.FuncDecl
}

// instSrcs resolves an expression to the composite literals it may hold —
// the instance-source channel of dispatch narrowing. complete=false
// means some producer was unresolvable (calls, opaque values); `new(T)`
// is a complete-but-empty source (zero value, no initializers).
func (ix *Index) instSrcs(pkg *packages.Package, enc *ast.FuncDecl, e ast.Expr, depth int, seen map[types.Object]bool) ([]srcInst, bool) {
	if depth > maxDispatchDepth || pkg == nil || pkg.TypesInfo == nil {
		return nil, false
	}
	switch ex := e.(type) {
	case *ast.CompositeLit:
		return []srcInst{{ex, pkg, enc}}, true
	case *ast.UnaryExpr:
		if cl, ok := ex.X.(*ast.CompositeLit); ok {
			return []srcInst{{cl, pkg, enc}}, true
		}
		return nil, false
	case *ast.Ident:
		obj := pkg.TypesInfo.ObjectOf(ex)
		v, ok := obj.(*types.Var)
		if !ok {
			return nil, false
		}
		if seen[v] {
			return nil, true
		}
		seen[v] = true
		defer delete(seen, v)
		var out []srcInst
		if enc != nil {
			if recvVar(enc, v) {
				// Method receiver: instances arrive as callers' receiver
				// expressions (`recv.M()` → instSrcs(recv) in the caller
				// frame); a self-recursive `c.M()` re-enters via seen.
				for _, r := range ix.callersOf(pkg, funcSymbolRef(pkg, enc)) {
					if r.possible {
						return nil, false
					}
					if !ix.callerOnPath(r) {
						continue
					}
					csel, ok := r.call.Fun.(*ast.SelectorExpr)
					if !ok {
						continue
					}
					sub, ok := ix.instSrcs(r.pkg, r.enclosing, csel.X, depth+1, seen)
					if !ok {
						return nil, false
					}
					out = append(out, sub...)
				}
			} else if idx := paramIndexOf(enc, v.Name()); idx >= 0 {
				for _, r := range ix.callersOf(pkg, funcSymbolRef(pkg, enc)) {
					if r.possible {
						return nil, false
					}
					if idx >= len(r.call.Args) || !ix.callerOnPath(r) {
						continue
					}
					sub, ok := ix.instSrcs(r.pkg, r.enclosing, r.call.Args[idx], depth+1, seen)
					if !ok {
						return nil, false
					}
					out = append(out, sub...)
				}
			}
		}
		for _, r := range assignRHS(pkg.TypesInfo, enc, v) {
			sub, ok := ix.instSrcs(pkg, enc, r.expr, depth+1, seen)
			if !ok {
				return nil, false
			}
			out = append(out, sub...)
		}
		return out, true
	case *ast.CallExpr:
		// new(T): zero-value instance — a real source, no initializers.
		if id, ok := ex.Fun.(*ast.Ident); ok && id.Name == "new" {
			return nil, true
		}
		// T(x) conversion: the instance is x's instance.
		if tv, ok := pkg.TypesInfo.Types[ex.Fun]; ok && tv.IsType() && len(ex.Args) == 1 {
			return ix.instSrcs(pkg, enc, ex.Args[0], depth+1, seen)
		}
		return nil, false
	case *ast.ParenExpr:
		return ix.instSrcs(pkg, enc, ex.X, depth+1, seen)
	}
	return nil, false
}

// pkgVarLiterals finds composite literals initializing a package-level
// var — its ValueSpec or `var = literal` assigns in package scope or init.
func (ix *Index) pkgVarLiterals(v *types.Var) []*ast.CompositeLit {
	if v.Pkg() == nil {
		return nil
	}
	var out []*ast.CompositeLit
	for _, pkg := range append(ix.allExtras(), ix.pkgs...) {
		if pkg.PkgPath != v.Pkg().Path() || pkg.TypesInfo == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			for _, d := range f.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok {
					continue
				}
				for _, s := range gd.Specs {
					vs, ok := s.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, n := range vs.Names {
						if pkg.TypesInfo.ObjectOf(n) != v || i >= len(vs.Values) {
							continue
						}
						if cl, ok := vs.Values[i].(*ast.CompositeLit); ok {
							out = append(out, cl)
						}
					}
				}
			}
			var enc *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok {
					enc = fn
				}
				ae, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				// init-time assigns to the package var — kept when the
				// enclosing func is on the product path or unscoped.
				if !ix.siteOnPath(pkg, enc) {
					return true
				}
				for i, l := range ae.Lhs {
					lid, ok := l.(*ast.Ident)
					if !ok || pkg.TypesInfo.ObjectOf(lid) != v || i >= len(ae.Rhs) {
						continue
					}
					if cl, ok := ae.Rhs[i].(*ast.CompositeLit); ok {
						out = append(out, cl)
					}
				}
				return true
			})
		}
	}
	return out
}

// stringVals evaluates e to the set of constant strings it may take.
// complete=false means some path was not evaluable — callers must treat
// the result as unusable (widening to all impls), never as partial truth.
func (ix *Index) stringVals(pkg *packages.Package, enc *ast.FuncDecl, e ast.Expr, fuel int) (map[string]bool, bool) {
	vals := map[string]bool{}
	fuelLeft := fuel
	ok := ix.stringValsInto(pkg, enc, e, 0, vals, &fuelLeft, map[types.Object]bool{})
	return vals, ok
}

// stringValsInto is the recursive engine behind stringVals.
func (ix *Index) stringValsInto(pkg *packages.Package, enc *ast.FuncDecl, e ast.Expr, depth int, out map[string]bool, fuel *int, seen map[types.Object]bool) bool {
	if *fuel <= 0 || depth > maxDispatchDepth || pkg == nil || pkg.TypesInfo == nil {
		return false
	}
	*fuel--
	info := pkg.TypesInfo
	switch ex := e.(type) {
	case *ast.BasicLit:
		if s, err := strconv.Unquote(ex.Value); err == nil {
			out[s] = true
			return true
		}
		return false
	case *ast.Ident:
		obj := info.ObjectOf(ex)
		if cn, ok := obj.(*types.Const); ok && cn.Val() != nil && cn.Val().Kind() == constant.String {
			out[constant.StringVal(cn.Val())] = true
			return true
		}
		v, ok := obj.(*types.Var)
		if !ok {
			return false
		}
		// Cyclic value flow (`src = f(src)` chains): a var being evaluated
		// upstream contributes nothing from this re-entry — the acyclic
		// producers already feed the outer fixpoint. All supported
		// transforms are substring-preserving, so no new atoms are lost.
		if seen[v] {
			return true
		}
		seen[v] = true
		defer delete(seen, v)
		// Parameter: climb to on-path callers and eval the passed arg.
		if enc != nil && paramIndexOf(enc, v.Name()) >= 0 {
			idx := paramIndexOf(enc, v.Name())
			refs := ix.callersOf(pkg, funcSymbolRef(pkg, enc))
			n := 0
			for _, r := range refs {
				if r.possible {
					return false
				}
				if idx >= len(r.call.Args) || !ix.callerOnPath(r) {
					continue
				}
				n++
				if !ix.stringValsInto(r.pkg, r.enclosing, r.call.Args[idx], depth+1, out, fuel, seen) {
					return false
				}
			}
			return n > 0
		}
		// Local var: union of its assignments.
		rhs := assignRHS(info, enc, obj)
		if len(rhs) == 0 {
			return false
		}
		for _, r := range rhs {
			if r.multi {
				// slot N of a multi-result call
				if !ix.stringValsCallResult(pkg, enc, r.expr, r.idx, out, depth, fuel, seen) {
					return false
				}
				continue
			}
			if _, ok := r.expr.(*ast.CallExpr); ok {
				// single-result call — semantics table decides; plain
				// calls are not evaluable.
				if !ix.stringValsCallResult(pkg, enc, r.expr, 0, out, depth, fuel, seen) {
					return false
				}
				continue
			}
			if !ix.stringValsInto(pkg, enc, r.expr, depth+1, out, fuel, seen) {
				return false
			}
		}
		return true
	case *ast.SelectorExpr:
		// `x.Scheme` where x holds a url.Parse result: scheme of each
		// evaluated source string, computed by net/url in the analyzer.
		if ex.Sel.Name == "Scheme" {
			return ix.schemeVals(pkg, enc, ex.X, depth, out, fuel, seen)
		}
		// Any other field read (c.Src): the instance-sensitive producer
		// set — literal initializers of x's possible instances plus
		// overlapping statement writes (see fieldValueExprs).
		fv, ok := info.ObjectOf(ex.Sel).(*types.Var)
		if !ok {
			return false
		}
		if seen[fv] {
			return true
		}
		seen[fv] = true
		defer delete(seen, fv)
		exprs, ok := ix.fieldValueExprs(pkg, enc, ex, depth, seen)
		if !ok {
			return false
		}
		for _, fe := range exprs {
			if !ix.stringValsInto(fe.pkg, fe.enc, fe.expr, depth+1, out, fuel, seen) {
				return false
			}
		}
		return true
	case *ast.CallExpr:
		// Semantic-known string transforms; everything else unknown.
		return ix.stringValsCallResult(pkg, enc, ex, 0, out, depth, fuel, seen)
	case *ast.IndexExpr:
		// `vs[i]` where vs holds a strings.Split result — the i-th
		// fragment of each evaluated input; out-of-range means that
		// arm is dead and contributes no value (not incompleteness).
		return ix.splitVals(pkg, enc, ex, depth, out, fuel, seen)
	case *ast.ParenExpr:
		return ix.stringValsInto(pkg, enc, ex.X, depth+1, out, fuel, seen)
	}
	return false
}

// splitVals evaluates s[constIdx] for slice vars produced by
// strings.Split/SplitN. An out-of-range index contributes nothing — the
// producing arm is unreachable for that input, which is a fact, not an
// unknown. Non-split provenance or a non-constant index fails closed.
func (ix *Index) splitVals(pkg *packages.Package, enc *ast.FuncDecl, ie *ast.IndexExpr, depth int, out map[string]bool, fuel *int, seen map[types.Object]bool) bool {
	info := pkg.TypesInfo
	if info == nil {
		return false
	}
	st, ok := info.TypeOf(ie.X).Underlying().(*types.Slice)
	if !ok || !types.Identical(st.Elem(), types.Typ[types.String]) {
		return false
	}
	idxVal := info.Types[ie.Index].Value
	if idxVal == nil {
		return false
	}
	i64, ok := constant.Int64Val(idxVal)
	if !ok {
		return false
	}
	base, ok := ie.X.(*ast.Ident)
	if !ok {
		return false
	}
	obj := info.ObjectOf(base)
	found := false
	for _, r := range assignRHS(info, enc, obj) {
		ce, ok := r.expr.(*ast.CallExpr)
		if !ok || len(ce.Args) < 2 {
			continue
		}
		fn, _ := calleeObject(info, ce.Fun).(*types.Func)
		if fn == nil || fn.Pkg() == nil || fn.Pkg().Path() != "strings" ||
			(fn.Name() != "Split" && fn.Name() != "SplitN") {
			continue
		}
		srcVals := map[string]bool{}
		if !ix.stringValsInto(pkg, enc, ce.Args[0], depth+1, srcVals, fuel, seen) {
			return false
		}
		sepVals := map[string]bool{}
		if !ix.stringValsInto(pkg, enc, ce.Args[1], depth+1, sepVals, fuel, seen) {
			return false
		}
		found = true
		for s := range srcVals {
			for sep := range sepVals {
				var parts []string
				if fn.Name() == "SplitN" && len(ce.Args) >= 3 {
					nv := info.Types[ce.Args[2]].Value
					if nv == nil {
						return false
					}
					n, ok := constant.Int64Val(nv)
					if !ok {
						return false
					}
					parts = strings.SplitN(s, sep, int(n))
				} else {
					parts = strings.Split(s, sep)
				}
				if int(i64) < len(parts) {
					out[parts[i64]] = true
				}
			}
		}
	}
	return found
}

// queryGetVals evaluates `q.Get(k)` where q holds u.Query() of a
// url.Parse-produced URL — const-folded via the analyzer's own net/url.
func (ix *Index) queryGetVals(pkg *packages.Package, enc *ast.FuncDecl, ce *ast.CallExpr, depth int, out map[string]bool, fuel *int, seen map[types.Object]bool) bool {
	sel, ok := ce.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Get" || len(ce.Args) != 1 {
		return false
	}
	info := pkg.TypesInfo
	if info == nil || !strings.Contains(info.TypeOf(sel.X).String(), "url.Values") {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	urlVals := map[string]bool{}
	found := false
	for _, r := range assignRHS(info, enc, info.ObjectOf(id)) {
		// q = u.Query() — evaluate the receiver's URL source.
		inner, ok := r.expr.(*ast.CallExpr)
		if !ok {
			continue
		}
		isel, ok := inner.Fun.(*ast.SelectorExpr)
		if !ok || isel.Sel.Name != "Query" {
			continue
		}
		ifn, _ := calleeObject(info, inner.Fun).(*types.Func)
		if ifn == nil || ifn.Name() != "Query" {
			continue
		}
		found = true
		if !ix.urlSourceVals(pkg, enc, isel.X, depth+1, urlVals, fuel, seen) {
			return false
		}
	}
	if !found {
		return false
	}
	keyVals := map[string]bool{}
	if !ix.stringValsInto(pkg, enc, ce.Args[0], depth+1, keyVals, fuel, seen) {
		return false
	}
	for s := range urlVals {
		u, err := url.Parse(stripForcedPrefix(s))
		if err != nil {
			return false
		}
		for k := range keyVals {
			out[u.Query().Get(k)] = true
		}
	}
	return true
}

// urlSourceVals resolves an expression denoting a *url.URL (a var
// assigned a Parse result) to the source strings parsed into it.
func (ix *Index) urlSourceVals(pkg *packages.Package, enc *ast.FuncDecl, e ast.Expr, depth int, out map[string]bool, fuel *int, seen map[types.Object]bool) bool {
	id, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	info := pkg.TypesInfo
	obj := info.ObjectOf(id)
	// Parameter: the URL arrives via caller args — climb on-path callers.
	if v, ok := obj.(*types.Var); ok && enc != nil {
		if idx := paramIndexOf(enc, v.Name()); idx >= 0 {
			found := false
			for _, r := range ix.callersOf(pkg, funcSymbolRef(pkg, enc)) {
				if r.possible {
					return false
				}
				if idx >= len(r.call.Args) || !ix.callerOnPath(r) {
					continue
				}
				found = true
				if !ix.urlSourceVals(r.pkg, r.enclosing, r.call.Args[idx], depth+1, out, fuel, seen) {
					return false
				}
			}
			return found
		}
	}
	found := false
	for _, r := range assignRHS(info, enc, obj) {
		ce, ok := r.expr.(*ast.CallExpr)
		if !ok || len(ce.Args) == 0 {
			continue
		}
		fn, _ := calleeObject(info, ce.Fun).(*types.Func)
		if fn == nil || fn.Name() != "Parse" {
			continue
		}
		sig, _ := fn.Type().(*types.Signature)
		if sig == nil || sig.Results() == nil || sig.Results().Len() == 0 ||
			!strings.Contains(sig.Results().At(0).Type().String(), "url.URL") {
			continue
		}
		found = true
		if !ix.stringValsInto(pkg, enc, ce.Args[0], depth+1, out, fuel, seen) {
			return false
		}
	}
	return found
}

// schemeVals evaluates `.Scheme` on an expression whose assignments are
// url.Parse-style calls — the scheme of each source-string value,
// computed by the analyzer's own net/url.
func (ix *Index) schemeVals(pkg *packages.Package, enc *ast.FuncDecl, base ast.Expr, depth int, out map[string]bool, fuel *int, seen map[types.Object]bool) bool {
	id, ok := base.(*ast.Ident)
	if !ok {
		return false
	}
	obj := pkg.TypesInfo.ObjectOf(id)
	srcVals := map[string]bool{}
	found := false
	for _, r := range assignRHS(pkg.TypesInfo, enc, obj) {
		ce, ok := r.expr.(*ast.CallExpr)
		if !ok || len(ce.Args) == 0 {
			continue
		}
		fn, _ := calleeObject(pkg.TypesInfo, ce.Fun).(*types.Func)
		if fn == nil || fn.Name() != "Parse" {
			continue
		}
		sig, _ := fn.Type().(*types.Signature)
		if sig == nil || sig.Results() == nil || sig.Results().Len() == 0 ||
			!strings.Contains(sig.Results().At(0).Type().String(), "url.URL") {
			continue
		}
		found = true
		if !ix.stringValsInto(pkg, enc, ce.Args[0], depth+1, srcVals, fuel, seen) {
			return false
		}
	}
	if !found {
		return false
	}
	for s := range srcVals {
		u, err := url.Parse(stripForcedPrefix(s))
		if err != nil || u.Scheme == "" {
			return false
		}
		out[u.Scheme] = true
	}
	return true
}

// stringValsCallResult evaluates one result position of a semantic-known
// string call into out. The semantics come from the knowledge table
// (string_semantics): identity_if_schemed / forced_split / subdir_split.
func (ix *Index) stringValsCallResult(pkg *packages.Package, enc *ast.FuncDecl, call ast.Expr, resultIdx int, out map[string]bool, depth int, fuel *int, seen map[types.Object]bool) bool {
	ce, ok := call.(*ast.CallExpr)
	if !ok || len(ce.Args) == 0 || pkg.TypesInfo == nil {
		return false
	}
	fn, _ := calleeObject(pkg.TypesInfo, ce.Fun).(*types.Func)
	if fn == nil || fn.Pkg() == nil {
		return false
	}
	// url.Values.Get on a Query() result — evaluated by the analyzer's
	// own net/url, no knowledge entry needed.
	if fn.Name() == "Get" {
		if sig, _ := fn.Type().(*types.Signature); sig != nil && sig.Recv() != nil &&
			strings.Contains(sig.Recv().Type().String(), "url.Values") {
			return ix.queryGetVals(pkg, enc, ce, depth, out, fuel, seen)
		}
	}
	sem, ok := ix.kb().StringSemantics[fn.Pkg().Path()+"."+fn.Name()]
	if !ok {
		return false
	}
	argVals := map[string]bool{}
	if !ix.stringValsInto(pkg, enc, ce.Args[0], depth+1, argVals, fuel, seen) {
		return false
	}
	switch sem {
	case "identity_if_schemed":
		// Result is arg0 verbatim when arg0 parses as a URL with a
		// non-empty scheme (forced `x::` prefix allowed and preserved);
		// otherwise the result is unknowable.
		for v := range argVals {
			u, err := url.Parse(stripForcedPrefix(v))
			if err != nil || u.Scheme == "" {
				return false
			}
			out[v] = true
		}
		return true
	case "forced_split":
		// Returns (prefix-or-"", rest) for `x::rest`; else ("", arg).
		for v := range argVals {
			f, rest := splitForcedPrefix(v)
			if resultIdx == 0 {
				out[f] = true
			} else {
				out[rest] = true
			}
		}
		return true
	case "subdir_split":
		// Returns (base, subdir): base keeps the scheme.
		for v := range argVals {
			if resultIdx == 0 {
				base, _ := splitSubdir(v)
				out[base] = true
			}
		}
		return true
	}
	return false
}

// pkgOfFile finds which loaded package owns the file containing pos —
// composite literals recovered from other packages carry their own
// TypesInfo.
func (ix *Index) pkgOfFile(n ast.Node) *packages.Package {
	if n == nil {
		return nil
	}
	fpos := ix.fset.Position(n.Pos()).Filename
	for _, p := range append(ix.allExtras(), ix.pkgs...) {
		for _, f := range p.Syntax {
			if ix.fset.Position(f.Pos()).Filename == fpos {
				return p
			}
		}
	}
	return nil
}

var forcedPrefixRe = regexp.MustCompile(`^([A-Za-z0-9]+)::(.+)$`)

func stripForcedPrefix(s string) string {
	_, rest := splitForcedPrefix(s)
	return rest
}

func splitForcedPrefix(s string) (string, string) {
	if ms := forcedPrefixRe.FindStringSubmatch(s); ms != nil {
		return ms[1], ms[2]
	}
	return "", s
}

// splitSubdir mirrors go-getter's SourceDirSubdir: a "//" after the
// scheme's "://" (and before any "?") splits (base, subdir); the query
// tail of the subdir moves back onto base.
func splitSubdir(src string) (string, string) {
	stop := len(src)
	if idx := strings.Index(src, "?"); idx > -1 {
		stop = idx
	}
	offset := 0
	if idx := strings.Index(src[:stop], "://"); idx > -1 {
		offset = idx + 3
	}
	idx := strings.Index(src[offset:stop], "//")
	if idx == -1 {
		return src, ""
	}
	idx += offset
	subdir := src[idx+2:]
	src = src[:idx]
	if idx = strings.Index(subdir, "?"); idx > -1 {
		query := subdir[idx:]
		subdir = subdir[:idx]
		src += query
	}
	return src, subdir
}

// namedTypeName resolves an expression's type to its named type name
// (pointer receiver methods live on *T but the impl key uses T).
func namedTypeName(t types.Type) string {
	for {
		if p, ok := t.(*types.Pointer); ok {
			t = p.Elem()
			continue
		}
		break
	}
	if n, ok := t.(*types.Named); ok && n.Obj() != nil {
		return n.Obj().Name()
	}
	return ""
}
