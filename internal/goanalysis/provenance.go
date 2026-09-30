package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/tools/go/packages"

	"example.com/vuln-analyzer/internal/domain"
)

// maxTraceHops bounds how far argument provenance follows identifiers into
// callers. Deeper chains resolve to UNKNOWN (a limitation), not a guess.
const maxTraceHops = 2

// maxExprDepth bounds structural recursion through a single expression —
// binary/selector/paren chains and composite literals. Real expressions
// stay under ~50; generated dep code and adversarial input can nest far
// deeper, where recursion would exhaust the stack before any check fires.
const maxExprDepth = 400

// enterExpr budgets one expression-nesting level; false past
// maxExprDepth, where the caller must stop recursing and yield UNKNOWN.
// Pair with leaveExpr via defer.
func (ix *Index) enterExpr() bool {
	if ix.exprDepth >= maxExprDepth {
		return false
	}
	ix.exprDepth++
	return true
}

func (ix *Index) leaveExpr() { ix.exprDepth-- }

// hops is the effective caller-climb bound: TraceArgumentBound may raise
// it for a single trace during gap analysis.
func (ix *Index) hops() int {
	if ix.hopLimit > 0 {
		return ix.hopLimit
	}
	return maxTraceHops
}

// TraceArgumentBound is TraceArgument with an explicit caller-climb
// budget. The gap-analysis loop uses it when the default bound left an
// argument origin unresolved.
func (ix *Index) TraceArgumentBound(ctx context.Context, site domain.CallSite, argIndex, hops int) (domain.DataFlow, []domain.Evidence, error) {
	ix.mu.Lock()
	ix.hopLimit = hops
	ix.mu.Unlock()
	defer func() {
		ix.mu.Lock()
		ix.hopLimit = 0
		ix.mu.Unlock()
	}()
	return ix.TraceArgument(ctx, site, argIndex)
}

// TraceArgument classifies the data origin of the argument at argIndex of
// the call site (File+Line locate the call expression).
func (ix *Index) TraceArgument(ctx context.Context, site domain.CallSite, argIndex int) (domain.DataFlow, []domain.Evidence, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	flow := domain.DataFlow{
		Sink:   site,
		Origin: domain.OriginUnknown,
	}
	var ev []domain.Evidence
	if err := ix.load(ctx); err != nil {
		return flow, nil, err
	}
	call, enc, pkg, err := ix.callAt(site)
	if err != nil {
		return flow, nil, err
	}
	flow.Arg = argIndex
	if argIndex >= len(call.Args) {
		return flow, nil, fmt.Errorf("call site has %d args, arg %d requested", len(call.Args), argIndex)
	}
	flow.PayloadUnproven = payloadUnprovenParameter(pkg, call, argIndex)
	// Collect the transformation chain: every call the traced value passes
	// through, recorded by classifyCall while txBuf is set. Held under the
	// same mutex as the rest of the trace — nil outside TraceArgument.
	var tx []domain.CallSite
	ix.txBuf = &tx
	ix.traceSeen = map[types.Object]bool{}
	ix.paramSeen = map[string]bool{}
	ix.paramCache = map[string]classifyResult{}
	ix.classifyCache = map[classifyKey]classifyResult{}
	ix.evalBudget = maxEvalBudget
	origin, why := ix.classify(pkg, enc, call.Args[argIndex], 0)
	ix.txBuf = nil
	ix.txSeen = nil
	ix.traceSeen = nil
	ix.paramSeen = nil
	ix.paramCache = nil
	ix.classifyCache = nil
	ix.evalBudget = 0
	flow.Origin = origin
	flow.Summary = why
	if v, ok := exprIntValue(pkg.TypesInfo, call.Args[argIndex]); ok {
		flow.Value = &v
	}
	flow.Transformations = dedupSites(tx)
	flow.Source = site
	src, _ := ix.nodeSource(call)
	ev = append(ev, domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityStructural,
		Source:  "ast argument trace",
		Tool:    "vuln-analyzer/goanalysis",
		File:    site.File,
		Content: src,
	})
	return flow, ev, nil
}

// callAt finds the CallExpr at the File:Line position of site. Product
// packages are searched first, then dependency packages loaded on demand
// (dep-internal sink sites resolve to module-cache/replaced-dep paths).
// When the site was recorded under a load the extras cache later evicted,
// its AST is gone from memory — reload the owning package by file query
// and rescan once before reporting failure.
func (ix *Index) callAt(site domain.CallSite) (*ast.CallExpr, *ast.FuncDecl, *packages.Package, error) {
	if call, enc, pkg := ix.scanCallAt(site); call != nil {
		return call, enc, pkg, nil
	}
	if _, err := ix.loadExtra(ix.ctxOr(nil), "file="+site.File); err == nil {
		if call, enc, pkg := ix.scanCallAt(site); call != nil {
			return call, enc, pkg, nil
		}
	}
	return nil, nil, nil, fmt.Errorf("call site %s:%d not found", site.File, site.Line)
}

func (ix *Index) scanCallAt(site domain.CallSite) (*ast.CallExpr, *ast.FuncDecl, *packages.Package) {
	for _, pkg := range append(append([]*packages.Package{}, ix.pkgs...), ix.allExtras()...) {
		for _, f := range pkg.Syntax {
			var found *ast.CallExpr
			var enc *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				if found != nil {
					return false
				}
				switch n := n.(type) {
				case *ast.FuncDecl:
					enc = n
				case *ast.CallExpr:
					p := ix.fset.Position(n.Lparen)
					if p.Filename == site.File && p.Line == site.Line &&
						(site.Column == 0 || p.Column == site.Column) {
						found = n
						return false
					}
				}
				return true
			})
			if found != nil {
				return found, enc, pkg
			}
		}
	}
	return nil, nil, nil
}

// classify resolves the origin of an expression within a function.
// depth limits parameter-hopping into callers.
// classify memoizes per (expr, enc, depth) for the lifetime of one trace:
// the caller fan-out reaches the same subtrees along exponentially many
// paths. Cached UNKNOWNs may carry a guard cut from a sibling path —
// an honest under-approximation toward INCONCLUSIVE, never a safe claim.
func (ix *Index) classify(pkg *packages.Package, enc *ast.FuncDecl, expr ast.Expr, depth int) (domain.DataOrigin, string) {
	key := classifyKey{pkg: pkg, enc: enc, expr: expr, depth: depth}
	if ix.classifyCache != nil {
		if r, ok := ix.classifyCache[key]; ok {
			return r.origin, r.why
		}
	}
	if !ix.budgeted() {
		return domain.OriginUnknown, "evaluation budget exhausted"
	}
	if !ix.enterExpr() {
		return domain.OriginUnknown, "expression depth exceeded"
	}
	o, w := ix.classifyExpr(pkg, enc, expr, depth)
	ix.leaveExpr()
	// Why-strings compose upward — an uncapped trace embeds every child's
	// explanation and grows exponentially (multi-MB strings per memoized
	// entry is what blew the memory budget on md-render). Cap at every
	// return so each join inputs bounded pieces.
	w = capWhy(w)
	if ix.classifyCache != nil && len(ix.classifyCache) < maxClassifyCache {
		ix.classifyCache[key] = classifyResult{origin: o, why: w}
	}
	return o, w
}

// maxWhyLen bounds a single trace explanation. The cap applies at every
// classify return and at every cache store, so composed whys stay
// bounded — an uncapped entry set is a memory bomb on deep dep traces
// (entries × cap is the floor a trace cannot go below).
const maxWhyLen = 1024

func capWhy(s string) string {
	if len(s) <= maxWhyLen {
		return s
	}
	return s[:maxWhyLen] + "…"
}

func (ix *Index) classifyExpr(pkg *packages.Package, enc *ast.FuncDecl, expr ast.Expr, depth int) (domain.DataOrigin, string) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return domain.OriginConstant, "literal constant"
	case *ast.CompositeLit:
		// The literal's provenance is the merge of its elements — a
		// `&io.LimitedReader{R: connReader}` carries the reader's origin,
		// not the literal's shape. Empty literals stay constant.
		out := domain.OriginConstant
		var whys []string
		for _, el := range e.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			o, w := ix.classify(pkg, enc, el, depth)
			whys = append(whys, w)
			out = mergeOrigin(out, o)
		}
		if len(whys) == 0 {
			return domain.OriginConstant, "composite literal"
		}
		return out, fmt.Sprintf("composite literal {%s}", strings.Join(whys, "; "))
	case *ast.Ident:
		return ix.classifyIdent(pkg, enc, e, depth)
	case *ast.SelectorExpr:
		return ix.classifySelector(pkg, enc, e, depth)
	case *ast.CallExpr:
		return ix.classifyCall(pkg, enc, e, depth)
	case *ast.BinaryExpr:
		xo, xw := ix.classify(pkg, enc, e.X, depth)
		yo, yw := ix.classify(pkg, enc, e.Y, depth)
		return mergeOrigins(xo, xw, yo, yw)
	case *ast.UnaryExpr:
		if e.Op == token.ARROW {
			// A channel receive yields data from send sites, which the
			// trace does not inventory — not the channel's own origin.
			return domain.OriginUnknown, "channel receive: send sites not inventoried"
		}
		return ix.classify(pkg, enc, e.X, depth)
	case *ast.IndexExpr, *ast.IndexListExpr, *ast.SliceExpr:
		return ix.classify(pkg, enc, childExpr(e), depth)
	case *ast.ParenExpr:
		return ix.classify(pkg, enc, e.X, depth)
	case *ast.TypeAssertExpr:
		return ix.classify(pkg, enc, e.X, depth)
	case *ast.FuncLit:
		// A function literal is code, not runtime data.
		return domain.OriginConstant, "function literal"
	}
	return domain.OriginUnknown, fmt.Sprintf("unsupported expression %T", expr)
}

func childExpr(e ast.Expr) ast.Expr {
	switch v := e.(type) {
	case *ast.IndexExpr:
		return v.X
	case *ast.IndexListExpr:
		return v.X
	case *ast.SliceExpr:
		return v.X
	}
	return e
}

func (ix *Index) classifyIdent(pkg *packages.Package, enc *ast.FuncDecl, id *ast.Ident, depth int) (domain.DataOrigin, string) {
	// true/false/nil are builtin identifiers, not BasicLit — constants.
	if id.Name == "true" || id.Name == "false" || id.Name == "nil" {
		return domain.OriginConstant, "builtin literal " + id.Name
	}
	obj := pkg.TypesInfo.ObjectOf(id)
	if obj == nil {
		return domain.OriginUnknown, fmt.Sprintf("unresolved identifier %s", id.Name)
	}
	// named constant — definitionally constant regardless of declaration site
	if _, ok := obj.(*types.Const); ok {
		return domain.OriginConstant, "named constant " + id.Name
	}
	// A package qualifier or a bare function name is a static code
	// reference, not runtime data — the function's inputs/results are
	// classified at its call sites, not here.
	if _, ok := obj.(*types.PkgName); ok {
		return domain.OriginConstant, "package qualifier " + id.Name
	}
	if _, ok := obj.(*types.Func); ok {
		return domain.OriginConstant, "function reference " + id.Name
	}
	// function parameter: hop into callers of the enclosing function
	if v, ok := obj.(*types.Var); ok && isParam(enc, v) {
		return ix.traceParam(pkg, enc, v, depth)
	}
	// method receiver: hop into receiver expressions at caller sites —
	// `d.Peek()` inside `func (d decoder) unmarshalMessage` is fed by
	// whatever `x` evaluates to in `x.unmarshalMessage(...)` calls.
	if v, ok := obj.(*types.Var); ok && isReceiver(enc, v) {
		return ix.traceReceiver(pkg, enc, v, depth)
	}
	// package-level var/const: classify its initializer
	if decl := findVarInit(pkg, v(obj)); decl != nil {
		o, why := ix.classify(pkg, enc, decl, depth+1)
		return o, fmt.Sprintf("package-level %s <- %s", obj.Name(), why)
	}
	// local var: merge every assignment inside the function — branch and
	// case writes all reach the read, so origins join (worst wins);
	// element stores (m[k] = e) feed the container's origin too. A
	// var already being resolved on this trace is a cycle (x = f(x)).
	rhsList := ix.assigns(enc, obj)
	rhsList = append(rhsList, elemWriteRHSs(enc, obj)...)
	if ix.traceSeen == nil {
		ix.traceSeen = map[types.Object]bool{}
	}
	if ix.traceSeen[obj] {
		// Self-referential writes (`x = append(x, e)`, `x.f(x)`)
		// contribute no new origin: x's own origin is already being
		// merged by the outer classify of the same object.
		return domain.OriginConstant, fmt.Sprintf("local %s: self-reference", id.Name)
	}
	ix.traceSeen[obj] = true
	defer delete(ix.traceSeen, obj)
	var merged domain.DataOrigin
	var whys []string
	for _, rhs := range rhsList {
		o, w := ix.classify(pkg, enc, rhs, depth)
		whys = append(whys, w)
		merged = mergeOrigin(merged, o)
	}
	// populated by a call rather than assigned: out-parameters f(..., &v),
	// slice destinations io.ReadFull(r, buf), receiver mutations v.Write(x).
	if o, why, ok := ix.populatedByCall(pkg, enc, obj, depth, ix.topEval(pkg, enc)); ok {
		merged = mergeOrigin(merged, o)
		whys = append(whys, why)
	}
	// Unsafe pointer stores `*(*T)(unsafe.Pointer(&v)) = e` populate the
	// variable through a dereference — the stored value's origin applies.
	if rhsList := derefWriteRHSs(enc, obj); len(rhsList) > 0 {
		for _, rhs := range rhsList {
			o, w := ix.classify(pkg, enc, rhs, depth)
			merged = mergeOrigin(merged, o)
			whys = append(whys, "deref-write: "+w)
		}
	}
	// `a, b := f()` — the shared producing call carries the origin;
	// only the result index bound to this variable is evaluated so an
	// error branch cannot taint the payload result.
	if rhs, ridx := multiAssignRHS(enc, obj, pkg.TypesInfo); rhs != nil {
		var o domain.DataOrigin
		var w string
		if call, isCall := rhs.(*ast.CallExpr); isCall {
			o, w = ix.evalCallResult(pkg, enc, call, ridx, ix.topEval(pkg, enc), depth)
		} else {
			o, w = ix.classify(pkg, enc, rhs, depth)
		}
		merged = mergeOrigin(merged, o)
		whys = append(whys, "multi-assign: "+w)
	}
	if merged != "" {
		return merged, fmt.Sprintf("local %s <- {%s}", id.Name, strings.Join(whys, " | "))
	}
	// `for i, item := range X` binds i/item to elements of X — the
	// element provenance is the ranged container's origin.
	if rx := rangeBoundExpr(pkg, enc, obj); rx != nil {
		o, w := ix.classify(pkg, enc, rx, depth)
		return o, fmt.Sprintf("range over %s", w)
	}
	// `switch v := e.(type)` binds v to e asserted — the guard
	// expression carries the origin.
	if g := typeSwitchBoundExpr(enc, obj); g != nil {
		o, w := ix.classify(pkg, enc, g, depth)
		return o, fmt.Sprintf("type-switch over %s", w)
	}
	// Parameters of a FuncLit passed to a call (`m.Range(func(fd, v)
	// bool)`) are fed by that callee — they inherit the hosting call's
	// receiver and argument origins.
	if host := litHostCall(enc, obj); host != nil {
		eval := func(e ast.Expr, d int) (domain.DataOrigin, string) {
			return ix.classify(pkg, enc, e, d)
		}
		o, w := litHostOrigin(host, eval, depth)
		return o, fmt.Sprintf("local %s <- %s", id.Name, w)
	}
	// Accumulator-style vars written only through self-referential
	// updates (n++, n += e): the value derives from the compound
	// operands alone — no external origin.
	if acc, ok := selfAccumWrites(enc, obj); ok {
		out := domain.OriginConstant
		for _, rhs := range acc {
			o, _ := ix.classify(pkg, enc, rhs, depth)
			out = mergeOrigin(out, o)
		}
		return out, fmt.Sprintf("accumulator %s", id.Name)
	}
	return domain.OriginUnknown, fmt.Sprintf("identifier %s without resolvable initializer", id.Name)
}

// multiAssignRHS returns the single RHS expression when obj is bound by
// a multi-value assignment `a, b := f()` — localAssigns only pairs
// index-matched LHS/RHS, so the shared producing call is invisible to it —
// together with the result index obj is bound to (0 when unpaired).
func multiAssignRHS(enc *ast.FuncDecl, obj types.Object, info *types.Info) (ast.Expr, int) {
	if enc == nil || enc.Body == nil || obj == nil || info == nil {
		return nil, -1
	}
	var found ast.Expr
	idx := 0
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) <= len(as.Rhs) || len(as.Rhs) == 0 {
			return true
		}
		for i, lhs := range as.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && sameObject(info.ObjectOf(id), obj) {
				found = as.Rhs[0]
				idx = i
			}
		}
		return found == nil
	})
	return found, idx
}

// litHostCall returns the call consuming a FuncLit when obj is one of
// the literal's parameters — `m.Range(func(fd, v) bool {...})`: the
// callee feeds those parameters, so they inherit the hosting call's
// receiver/argument origins.
func litHostCall(enc *ast.FuncDecl, obj types.Object) *ast.CallExpr {
	if enc == nil || enc.Body == nil || obj == nil {
		return nil
	}
	var host *ast.CallExpr
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		if host != nil {
			return false
		}
		ce, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		for _, a := range ce.Args {
			lit, ok := a.(*ast.FuncLit)
			if !ok || lit.Type.Params == nil {
				continue
			}
			for _, f := range lit.Type.Params.List {
				for _, nm := range f.Names {
					if nm.Pos() == obj.Pos() {
						host = ce
						return false
					}
				}
			}
		}
		return true
	})
	return host
}

// litHostOrigin merges the origins feeding a callback's parameters:
// the hosting call's receiver plus its non-literal arguments — the
// callee invokes the literal with values derived from its inputs.
func litHostOrigin(host *ast.CallExpr, evalArg exprEval, depth int) (domain.DataOrigin, string) {
	out := domain.OriginConstant
	var parts []string
	if sel, ok := host.Fun.(*ast.SelectorExpr); ok {
		o, w := evalArg(sel.X, depth)
		parts = append(parts, "host recv "+w)
		out = mergeOrigin(out, o)
	}
	for _, a := range host.Args {
		if _, isLit := a.(*ast.FuncLit); isLit {
			continue
		}
		o, w := evalArg(a, depth)
		parts = append(parts, w)
		out = mergeOrigin(out, o)
	}
	return out, "host call {" + strings.Join(parts, " | ") + "}"
}

// typeSwitchBoundExpr returns the asserted expression when obj is the
// variable bound by `switch v := e.(type)` — the guard carries the
// origin of the value each case clause sees.
func typeSwitchBoundExpr(enc *ast.FuncDecl, obj types.Object) ast.Expr {
	if enc == nil || enc.Body == nil || obj == nil {
		return nil
	}
	var found ast.Expr
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		ts, ok := n.(*ast.TypeSwitchStmt)
		if !ok {
			return true
		}
		switch a := ts.Assign.(type) {
		case *ast.AssignStmt:
			for _, lhs := range a.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == obj.Name() {
					if ta, ok := a.Rhs[0].(*ast.TypeAssertExpr); ok {
						found = ta.X
					}
				}
			}
		}
		return found == nil
	})
	return found
}

// rangeBoundExpr returns the range source expression when obj is bound
// by a `for ... := range X` statement inside enc.
func rangeBoundExpr(pkg *packages.Package, enc *ast.FuncDecl, obj types.Object) ast.Expr {
	if enc == nil || enc.Body == nil || obj == nil || pkg.TypesInfo == nil {
		return nil
	}
	var found ast.Expr
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		rs, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		for _, b := range []ast.Expr{rs.Key, rs.Value} {
			if id, ok := b.(*ast.Ident); ok && sameObject(pkg.TypesInfo.ObjectOf(id), obj) {
				found = rs.X
			}
		}
		return found == nil
	})
	return found
}

// populatedByCall detects writes that flow into v through a call rather
// than an assignment:
//
//   - out-parameters `f(..., &v)`: DB/service scanners return their family
//     origin; unmarshal/decode families propagate the source's origin;
//   - slice destinations `io.ReadFull(r, buf)`, `x.Read(buf)`: v carries
//     the source reader's origin;
//   - receiver mutation `v.Write(arg)`, `v.ReadFrom(r)`: buffer-like
//     accumulators take their argument's origin.
//
// Every matching call contributes; origins merge worst-wins. eval resolves
// source expressions in the caller's frame (topEval for call-site args,
// the callee evaluator for forward body traces).
func (ix *Index) populatedByCall(pkg *packages.Package, enc *ast.FuncDecl, obj types.Object, depth int, eval exprEval) (domain.DataOrigin, string, bool) {
	if enc == nil || enc.Body == nil || depth >= ix.hops() {
		return "", "", false
	}
	calls := ix.callsIn(enc)
	isObj := func(e ast.Expr) bool {
		if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
			e = u.X
		}
		id, ok := e.(*ast.Ident)
		return ok && sameObject(pkg.TypesInfo.ObjectOf(id), obj)
	}
	var merged domain.DataOrigin
	var whys []string
	merge := func(o domain.DataOrigin, why string) {
		merged = mergeOrigin(merged, o)
		whys = append(whys, why)
	}
	for _, call := range calls {
		fn, _ := calleeObject(pkg.TypesInfo, call.Fun).(*types.Func)
		if fn == nil {
			continue
		}
		// &v out-parameter
		for _, a := range call.Args {
			u, ok := a.(*ast.UnaryExpr)
			if !ok || u.Op != token.AND {
				continue
			}
			id, ok := u.X.(*ast.Ident)
			if !ok || !sameObject(pkg.TypesInfo.ObjectOf(id), obj) {
				continue
			}
			switch {
			case ix.isDBFunc(fn):
				merge(domain.OriginDatabase, fmt.Sprintf("%s populates &%s", fn.Name(), obj.Name()))
			case ix.isServiceCall(fn):
				merge(domain.OriginInternalService, fmt.Sprintf("%s populates &%s", fn.Name(), obj.Name()))
			default:
				// unmarshal/decode: origin of the *source* propagates — for
				// methods the source is the receiver (`dec.Decode(&x)`), for
				// package funcs the data argument (`json.Unmarshal(data, &x)`).
				if ix.kb().PopulateNames[fn.Name()] {
					var src ast.Expr
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
							src = sel.X
						}
					} else if len(call.Args) > 0 {
						src = call.Args[0]
					}
					if src != nil {
						o, w := eval(src, depth+1)
						merge(o, fmt.Sprintf("%s into &%s: %s", fn.Name(), obj.Name(), w))
					}
				}
			}
		}
		// slice/writer destination at a known position: f(src, ..., v, ...)
		// Builtins (append, copy, new) carry no package — they cannot be
		// knowledge-base populate entries, and fn.Pkg() is nil for them.
		if pkgOf := fn.Pkg(); pkgOf != nil {
			if idx, ok := ix.kb().SlicePopulateFuncs[pkgOf.Path()+"."+fn.Name()]; ok &&
				idx[0] < len(call.Args) && idx[1] < len(call.Args) && isObj(call.Args[idx[0]]) {
				o, w := eval(call.Args[idx[1]], depth+1)
				merge(o, fmt.Sprintf("%s into %s: %s", fn.Name(), obj.Name(), w))
				continue
			}
		}
		sel, isSel := call.Fun.(*ast.SelectorExpr)
		if !isSel {
			continue
		}
		// x.Read(v): the destination slice receives the reader's origin.
		if ix.kb().ReadIntoMethods[fn.Name()] && len(call.Args) > 0 && isObj(call.Args[0]) {
			o, w := eval(sel.X, depth+1)
			merge(o, fmt.Sprintf("%s into %s: %s", fn.Name(), obj.Name(), w))
			continue
		}
		// v.Write(arg)/v.ReadFrom(r): the accumulator takes arg's origin.
		if ix.kb().RecvMutateMethods[fn.Name()] && len(call.Args) > 0 && isObj(sel.X) {
			o, w := eval(call.Args[0], depth+1)
			merge(o, fmt.Sprintf("%s.%s(%s)", obj.Name(), fn.Name(), w))
		}
	}
	if merged == "" {
		return "", "", false
	}
	return merged, strings.Join(whys, "; "), true
}

// isDBFunc reports whether fn is a database/kv-store API — method on a
// driver type (sql.Rows, gorm.DB, mongo.Collection, redis.Client...) or a
// package-level helper in a known data-store package. Package paths and
// substrings come from the knowledge base (DBPkgs / DBPkgHints).
func (ix *Index) isDBFunc(fn *types.Func) bool {
	pkgPath := ""
	if fn.Pkg() != nil {
		pkgPath = fn.Pkg().Path()
	}
	if ix.isDBPkg(pkgPath) {
		return true
	}
	// receiver type in a data-store package (method values too)
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		if n := recvNamed(sig.Recv().Type()); n != nil && n.Obj() != nil && n.Obj().Pkg() != nil {
			return ix.isDBPkg(n.Obj().Pkg().Path())
		}
	}
	return false
}

// isDBPkg matches a package path against the knowledge-base data-store
// entries: exact paths first, then substring hints.
func (ix *Index) isDBPkg(pkgPath string) bool {
	if slices.Contains(ix.kb().DBPkgs, pkgPath) {
		return true
	}
	for _, h := range ix.kb().DBPkgHints {
		if strings.Contains(pkgPath, h) {
			return true
		}
	}
	return false
}

// recvNamed unwraps a receiver type to its *types.Named.
func recvNamed(t types.Type) *types.Named {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n
	}
	return nil
}

// isServiceCall detects RPC-stub methods: a receiver type whose package
// imports an RPC framework — generated *Client stubs. Framework import
// paths come from the knowledge base (ServiceCallPkgHints).
func (ix *Index) isServiceCall(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	n := recvNamed(sig.Recv().Type())
	if n == nil || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	for _, imp := range n.Obj().Pkg().Imports() {
		for _, h := range ix.kb().ServiceCallPkgHints {
			if strings.Contains(imp.Path(), h) {
				return true
			}
		}
	}
	return false
}

func isParam(enc *ast.FuncDecl, v *types.Var) bool {
	if enc == nil || enc.Type == nil || enc.Type.Params == nil {
		return false
	}
	for _, f := range enc.Type.Params.List {
		for _, n := range f.Names {
			if n.Name == v.Name() {
				return true
			}
		}
	}
	return false
}

func v(obj types.Object) *types.Var {
	if v, ok := obj.(*types.Var); ok {
		return v
	}
	return nil
}

func findVarInit(pkg *packages.Package, v *types.Var) ast.Expr {
	if v == nil || v.Parent() == nil {
		return nil
	}
	for _, f := range pkg.Syntax {
		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || len(vs.Values) == 0 {
					continue
				}
				for i, n := range vs.Names {
					if pkg.TypesInfo.ObjectOf(n) == v && i < len(vs.Values) {
						return vs.Values[i]
					}
				}
			}
		}
	}
	return nil
}

// findLocalAssign finds an assignment `id = rhs` inside enc that dominates
// the argument identifier. MVP heuristic: the last AssignStmt/ValueSpec
// binding before the sink position.
func findLocalAssign(enc *ast.FuncDecl, obj types.Object) ast.Expr {
	if enc == nil || enc.Body == nil || obj == nil {
		return nil
	}
	var best ast.Expr
	var bestPos token.Pos
	_ = bestPos
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(n.Rhs) {
					continue
				}
				// definition equality via TypesInfo is not available here;
				// compare names + object identity through Defs/Uses is the
				// reliable way — fall back to name match within same scope.
				if id.Name == obj.Name() && (best == nil || n.Pos() > bestPos) {
					best = n.Rhs[i]
					bestPos = n.Pos()
				}
			}
		case *ast.ValueSpec:
			for i, n2 := range n.Names {
				if n2.Name == obj.Name() && i < len(n.Values) && (best == nil || n.Pos() > bestPos) {
					best = n.Values[i]
					bestPos = n.Pos()
				}
			}
		}
		return true
	})
	return best
}

// classifySelector handles field/method selections like r.Body, r.URL, os.Args.
// localAssigns collects every AssignStmt/ValueSpec RHS bound to obj inside
// enc — branch and case writes all reach the read, so the caller merges
// their origins (worst wins). findLocalAssign keeps the single last-write
// view for callers that only need a dominating statement.
func localAssigns(enc *ast.FuncDecl, obj types.Object) []ast.Expr {
	if enc == nil || enc.Body == nil || obj == nil {
		return nil
	}
	var out []ast.Expr
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			// `a, b := f()` pairs multiple LHS to a single call — the
			// result index is needed to avoid merging sibling results
			// (error branches), so multiAssignRHS owns those writes.
			if len(n.Lhs) > len(n.Rhs) {
				return true
			}
			for i, lhs := range n.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && id.Name == obj.Name() && i < len(n.Rhs) {
					out = append(out, n.Rhs[i])
				}
			}
		case *ast.ValueSpec:
			for i, n2 := range n.Names {
				if n2.Name == obj.Name() && i < len(n.Values) {
					out = append(out, n.Values[i])
				}
			}
		}
		return true
	})
	return out
}

// selfAccumWrites reports whether obj is written exclusively through
// self-referential updates — n++ or n op= e — with no plain `=`/`:=`
// assignment anywhere in the body (those are handled by localAssigns).
// On success it returns the compound-assign RHS expressions whose origins
// feed the accumulated value; a bare IncDec contributes nothing.
func selfAccumWrites(enc *ast.FuncDecl, obj types.Object) ([]ast.Expr, bool) {
	if enc == nil || enc.Body == nil || obj == nil {
		return nil, false
	}
	var rhs []ast.Expr
	ok, seen := true, false
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for i, lhs := range n.Lhs {
				id, isId := lhs.(*ast.Ident)
				if !isId || id.Name != obj.Name() {
					continue
				}
				if n.Tok == token.ASSIGN || n.Tok == token.DEFINE {
					ok = false
					return false
				}
				seen = true
				if i < len(n.Rhs) {
					rhs = append(rhs, n.Rhs[i])
				}
			}
		case *ast.IncDecStmt:
			if id, isId := n.X.(*ast.Ident); isId && id.Name == obj.Name() {
				seen = true
			}
		}
		return ok
	})
	if !ok || !seen {
		return nil, false
	}
	return rhs, true
}

// derefWriteRHSs returns the RHSs of assignments that write obj through
// a pointer dereference — `*(*T)(unsafe.Pointer(&x)) = e` — which
// localAssigns cannot see because the LHS is not a bare identifier.
// The value stored still determines what later reads of x contain.
func derefWriteRHSs(enc *ast.FuncDecl, obj types.Object) []ast.Expr {
	if enc == nil || enc.Body == nil || obj == nil {
		return nil
	}
	var out []ast.Expr
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != len(as.Rhs) {
			return true
		}
		for i, lhs := range as.Lhs {
			star, ok := lhs.(*ast.StarExpr)
			if !ok {
				continue
			}
			hit := false
			ast.Inspect(star.X, func(m ast.Node) bool {
				if hit {
					return false
				}
				if un, ok := m.(*ast.UnaryExpr); ok && un.Op == token.AND {
					if id, ok := un.X.(*ast.Ident); ok && id.Name == obj.Name() {
						hit = true
						return false
					}
				}
				return true
			})
			if hit {
				out = append(out, as.Rhs[i])
			}
		}
		return true
	})
	return out
}

// elemWriteRHSs returns the RHSs of writes that store through an index,
// slice, or field selection rooted at obj — `m[k] = e`, `b[i] ^= e`,
// `x.f = e` — which localAssigns cannot see because the LHS is not a
// bare identifier. The stored value's origin feeds the container's
// provenance.
func elemWriteRHSs(enc *ast.FuncDecl, obj types.Object) []ast.Expr {
	if enc == nil || enc.Body == nil || obj == nil {
		return nil
	}
	var out []ast.Expr
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			if lhsRootIdent(lhs) != obj.Name() {
				continue
			}
			if i < len(as.Rhs) {
				out = append(out, as.Rhs[i])
			} else {
				out = append(out, as.Rhs...)
			}
		}
		return true
	})
	return out
}

// lhsRootIdent unwraps an index/slice/field-selection LHS to the
// identifier naming the rooted container — `a.b[i]` roots at `a`. A
// bare identifier roots at itself; dereferences return "" (covered by
// derefWriteRHSs).
func lhsRootIdent(e ast.Expr) string {
	for {
		switch v := e.(type) {
		case *ast.IndexExpr:
			e = v.X
		case *ast.IndexListExpr:
			e = v.X
		case *ast.SliceExpr:
			e = v.X
		case *ast.SelectorExpr:
			e = v.X
		case *ast.ParenExpr:
			e = v.X
		case *ast.StarExpr:
			return ""
		case *ast.Ident:
			return v.Name
		default:
			return ""
		}
	}
}

// assigns memoizes localAssigns — the body walk repeats for every traced
// identifier of a function, and the result is immutable for the index.
func (ix *Index) assigns(enc *ast.FuncDecl, obj types.Object) []ast.Expr {
	if ix.assignCache == nil {
		ix.assignCache = map[assignKey][]ast.Expr{}
	}
	k := assignKey{enc: enc, obj: obj}
	if rhs, ok := ix.assignCache[k]; ok {
		return rhs
	}
	rhs := localAssigns(enc, obj)
	if len(ix.assignCache) < maxAuxCache {
		ix.assignCache[k] = rhs
	}
	return rhs
}

// callsIn memoizes the call-expression list of a function body —
// populatedByCall walks it for every populated variable.
func (ix *Index) callsIn(enc *ast.FuncDecl) []*ast.CallExpr {
	if ix.callListCache == nil {
		ix.callListCache = map[*ast.FuncDecl][]*ast.CallExpr{}
	}
	if calls, ok := ix.callListCache[enc]; ok {
		return calls
	}
	var calls []*ast.CallExpr
	if enc != nil && enc.Body != nil {
		ast.Inspect(enc.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				calls = append(calls, call)
			}
			return true
		})
	}
	if len(ix.callListCache) < maxAuxCache {
		ix.callListCache[enc] = calls
	}
	return calls
}

func (ix *Index) classifySelector(pkg *packages.Package, enc *ast.FuncDecl, e *ast.SelectorExpr, depth int) (domain.DataOrigin, string) {
	sel, ok := pkg.TypesInfo.Selections[e]
	if ok {
		recv := sel.Recv()
		if isHTTPRequest(recv) {
			return domain.OriginExternalUntrusted, fmt.Sprintf("field %s of *http.Request", e.Sel.Name)
		}
	}
	// os.Args accessed as selector expr os.Args
	if obj := pkg.TypesInfo.ObjectOf(e.Sel); obj != nil {
		if b, ok2 := obj.(*types.Var); ok2 && b.Pkg() != nil && b.Pkg().Path() == "os" && b.Name() == "Args" {
			return domain.OriginExternalUntrusted, "os.Args"
		}
	}
	// struct field read (r.prefetchCount): resolve through the field's
	// write sites — x.f = rhs assignments and T{f: rhs} literals found in
	// product source. Any unresolvable write contaminates the merged
	// origin (UNKNOWN); zero write sites fall through to the base.
	if sel, ok := pkg.TypesInfo.Selections[e]; ok && sel.Kind() == types.FieldVal {
		if fv, ok2 := sel.Obj().(*types.Var); ok2 {
			if o, why, ok3 := ix.fieldOrigin(fv, depth+1); ok3 {
				return o, fmt.Sprintf("field %s: %s", e.Sel.Name, why)
			}
			// No textual write sites: a mapstructure/env-tagged field is
			// populated by config-decoding machinery (viper, envconfig) —
			// reflection writes are invisible, but the tag is the honest
			// provenance marker. json/yaml tags stay UNKNOWN — they mark
			// API payload surfaces, not configuration.
			if ix.fieldConfigTagged(fv) {
				return domain.OriginConfiguration,
					fmt.Sprintf("field %s carries a config-decode tag (mapstructure/env)", e.Sel.Name)
			}
		}
	}
	// Package-qualified member (pkg.Const, pkg.Var, pkg.Func): the
	// selector's object resolves directly — constants are constant,
	// vars take their initializer's origin, a function name is a static
	// code reference (its inputs/results are classified at call sites).
	if _, isSel := pkg.TypesInfo.Selections[e]; !isSel {
		if obj := pkg.TypesInfo.ObjectOf(e.Sel); obj != nil {
			if _, isConst := obj.(*types.Const); isConst {
				return domain.OriginConstant, "named constant " + e.Sel.Name
			}
			if _, isFn := obj.(*types.Func); isFn {
				return domain.OriginConstant, "function reference " + e.Sel.Name
			}
			if vr, isVar := obj.(*types.Var); isVar {
				if init := findVarInit(pkg, vr); init != nil {
					o, w := ix.classify(pkg, enc, init, depth+1)
					return o, "package-level " + e.Sel.Name + " <- " + w
				}
			}
		}
	}
	// transparent selector: classify base — keep the enclosing func so the
	// base can resolve to a local variable (resp.Body -> resp assignment).
	return ix.classify(pkg, enc, e.X, depth)
}

// fieldConfigTagged locates the field's declaration and reports whether
// its struct tag marks a configuration-decoded value.
func (ix *Index) fieldConfigTagged(field *types.Var) bool {
	if ix.fieldTagCache == nil {
		ix.fieldTagCache = map[*types.Var]bool{}
	}
	// Pointer key: types.Var.Id() collides for same-named fields of
	// different structs in one package; pointer identity is exact within
	// a load and merely misses across reloads.
	if tagged, ok := ix.fieldTagCache[field]; ok {
		return tagged
	}
	tagged := ix.fieldConfigTaggedScan(field)
	ix.fieldTagCache[field] = tagged
	return tagged
}

func (ix *Index) fieldConfigTaggedScan(field *types.Var) bool {
	pkgPath := ""
	if field.Pkg() != nil {
		pkgPath = field.Pkg().Path()
	}
	for _, pkg := range ix.memberScope(pkgPath) {
		info := pkg.TypesInfo
		for _, f := range pkg.Syntax {
			found := false
			tagged := false
			ast.Inspect(f, func(n ast.Node) bool {
				if found {
					return false
				}
				fd, ok := n.(*ast.Field)
				if !ok {
					return true
				}
				for _, name := range fd.Names {
					if sameObject(info.ObjectOf(name), field) {
						found = true
						if fd.Tag != nil {
							tag := strings.Trim(fd.Tag.Value, "`")
							for _, k := range ix.kb().ConfigTagKeys {
								if _, ok := reflect.StructTag(tag).Lookup(k); ok {
									tagged = true
								}
							}
						}
						return false
					}
				}
				return true
			})
			if found {
				return tagged
			}
		}
	}
	return false
}

// fieldOrigin resolves the provenance of a struct field by scanning
// product packages for writes to it: `x.field = rhs` (any receiver of
// the same struct type — the field object is matched by identity) and
// `T{field: rhs}` composite literals. Each RHS is classified in its own
// enclosing function, so `r.f = count` inside a setter hops into the
// setter's callers through traceParam. Writes via reflection or pointer
// aliases are invisible — recorded as a limitation-shaped why.
// fieldWrite is one product-source assignment into a struct field.
type fieldWrite struct {
	pkg  *packages.Package
	enc  *ast.FuncDecl // nil for package-level writes
	rhs  ast.Expr
	base ast.Expr // LHS base expr (x in x.F=v); nil for literal inits
	pos  token.Pos
}

// fieldWriteSites scans the field's owner scope for writes to it:
// `x.field = rhs` assignments (any receiver of the same struct type —
// matched by field object identity) and `T{field: rhs}` literals. Product
// fields are matched in product packages; dependency fields in the loaded
// dep sources (plus product callers).
func (ix *Index) fieldWriteSites(field *types.Var) []fieldWrite {
	if ix.fieldWritesCache == nil {
		ix.fieldWritesCache = map[*types.Var]cachedFieldWrites{}
	}
	if c, ok := ix.fieldWritesCache[field]; ok && c.gen == ix.extrasGen {
		return c.sites
	}
	sites := ix.fieldWriteSitesScan(field)
	ix.fieldWritesCache[field] = cachedFieldWrites{gen: ix.extrasGen, sites: sites}
	return sites
}

// cachedFieldWrites records a write-site scan, tagged with the extras
// generation like callerCache — a newly loaded dep package may hold
// additional writes to the same field.
type cachedFieldWrites struct {
	gen   int
	sites []fieldWrite
}

func (ix *Index) fieldWriteSitesScan(field *types.Var) []fieldWrite {
	var sites []fieldWrite
	pkgPath := ""
	if field.Pkg() != nil {
		pkgPath = field.Pkg().Path()
	}
	owner := ix.fieldParentName(field)
	for _, pkg := range ix.memberScope(pkgPath) {
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
				switch n := n.(type) {
				case *ast.AssignStmt:
					for i, lhs := range n.Lhs {
						if !ix.writesField(info, lhs, field, owner) {
							continue
						}
						rhs := ast.Expr(nil)
						if i < len(n.Rhs) {
							rhs = n.Rhs[i]
						} else if len(n.Rhs) == 1 {
							// x.f, y = multiReturn(): the call produces it.
							rhs = n.Rhs[0]
						}
						if rhs != nil {
							var base ast.Expr
							if sel, ok := lhs.(*ast.SelectorExpr); ok {
								base = sel.X
							}
							sites = append(sites, fieldWrite{pkg, enc, rhs, base, n.Pos()})
						}
					}
				case *ast.CompositeLit:
					// `T{field: rhs}` — keyed elements write the field.
					// The composite's type disambiguates same-named
					// fields of different structs sharing an Id.
					ct := info.Types[n].Type
					if ct == nil {
						break
					}
					if p, ok := ct.(*types.Pointer); ok {
						ct = p.Elem()
					}
					clNamed := ""
					if nt, ok := ct.(*types.Named); ok && nt.Obj() != nil && nt.Obj().Pkg() != nil {
						clNamed = nt.Obj().Pkg().Path() + "." + nt.Obj().Name()
					}
					for _, elt := range n.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						id, ok := kv.Key.(*ast.Ident)
						if !ok {
							continue
						}
						obj := info.ObjectOf(id)
						match := obj == field ||
							(owner != "" && clNamed == owner && sameObject(obj, field))
						if match {
							sites = append(sites, fieldWrite{pkg, enc, kv.Value, nil, n.Pos()})
						}
					}
				}
				return true
			})
		}
	}
	return sites
}

func (ix *Index) fieldOrigin(field *types.Var, depth int) (domain.DataOrigin, string, bool) {
	if depth >= ix.hops() {
		return "", "", false
	}
	gen := ix.extrasGen
	if ix.fieldOriginCache == nil {
		ix.fieldOriginCache = map[fieldOriginKey]cachedFieldOrigin{}
	}
	key := fieldOriginKey{field: field, depth: depth}
	if c, ok := ix.fieldOriginCache[key]; ok && c.gen == gen {
		return c.origin, c.why, c.ok
	}
	o, w, ok := ix.fieldOriginScan(field, depth)
	if ix.extrasGen != gen {
		return domain.OriginUnknown, "dependency scope changed while resolving field origin", true
	}
	if ix.extrasGen == gen && len(ix.fieldOriginCache) < maxAuxCache {
		if ix.fieldOriginCache == nil {
			ix.fieldOriginCache = map[fieldOriginKey]cachedFieldOrigin{}
		}
		ix.fieldOriginCache[key] = cachedFieldOrigin{gen: gen, origin: o, why: capWhy(w), ok: ok}
	}
	return o, w, ok
}

// fieldOriginKey addresses one field-origin resolution: the field plus
// the remaining caller-hop depth (the same field resolves differently
// at different budgets).
type fieldOriginKey struct {
	field *types.Var
	depth int
}

// cachedFieldOrigin records a field-origin resolution, tagged with the
// extras generation like callerCache.
type cachedFieldOrigin struct {
	gen    int
	origin domain.DataOrigin
	why    string
	ok     bool
}

func (ix *Index) fieldOriginScan(field *types.Var, depth int) (domain.DataOrigin, string, bool) {
	sites := ix.fieldWriteSites(field)
	if len(sites) == 0 {
		return "", "", false
	}
	var merged domain.DataOrigin
	var whys []string
	for _, s := range sites {
		// Writes in dep functions outside the product-driven cone belong
		// to alternative module flows (e.g. a shipped cmd/ wiring
		// os.Args) — merging them would over-approximate the product's
		// data toward EXTERNAL_UNTRUSTED.
		if !ix.siteOnPath(s.pkg, s.enc) {
			continue
		}
		o, w := ix.classify(s.pkg, s.enc, s.rhs, depth+1)
		whys = append(whys, w)
		merged = mergeOrigin(merged, o)
	}
	return merged, fmt.Sprintf("%d write site(s): %s", len(sites), capWhy(strings.Join(whys, "; "))), true
}

// fieldAddressTaken reports whether any product code takes the field's
// address (&x.f) — such a pointer alias allows writes invisible to
// fieldWriteSites.
func (ix *Index) fieldAddressTaken(field *types.Var) bool {
	found := false
	pkgPath := ""
	if field.Pkg() != nil {
		pkgPath = field.Pkg().Path()
	}
	for _, pkg := range ix.memberScope(pkgPath) {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				if found {
					return false
				}
				u, ok := n.(*ast.UnaryExpr)
				if !ok || u.Op != token.AND {
					return true
				}
				if se, ok := u.X.(*ast.SelectorExpr); ok &&
					sameObject(info.ObjectOf(se.Sel), field) {
					found = true
					return false
				}
				return true
			})
			if found {
				return true
			}
		}
	}
	return false
}

// writesField reports whether the lhs expression assigns to the field —
// a direct x.f = v or an indexed/dereferenced variant like x.f[i] = v.
// Field objects are compared by object identity: same-named fields of
// different structs in one package share a types.Id, so the declaring
// type is checked too — the receiver path's parent named type must equal
// owner (fieldParentName). Fields of anonymous struct types (owner=="")
// match only by pointer identity — same-load objects; cross-load writes
// to anonymous-struct fields are indistinguishable by name alone.
func (ix *Index) writesField(info *types.Info, lhs ast.Expr, field *types.Var, owner string) bool {
	found := false
	ast.Inspect(lhs, func(n ast.Node) bool {
		se, ok := n.(*ast.SelectorExpr)
		if !ok {
			return !found
		}
		obj := info.ObjectOf(se.Sel)
		if obj == field {
			found = true
			return false
		}
		if !sameObject(obj, field) {
			return true
		}
		// Same Id, different object — accept only when the declaring
		// struct type's name matches the target's owner.
		sl, ok2 := info.Selections[se]
		if ok2 && owner != "" && selParentNamed(sl) == owner {
			found = true
			return false
		}
		return true
	})
	return found
}

// selParentNamed returns the qualified name ("pkg.T") of the named type
// declaring the selected field — the receiver itself for direct fields,
// the embedded field's type for promoted selections like x.embedded.f.
// Returns "" for anonymous declaring structs.
func selParentNamed(sl *types.Selection) string {
	if sl == nil {
		return ""
	}
	t := sl.Recv()
	idx := sl.Index()
	for i := 0; i+1 < len(idx); i++ {
		tt := derefType(t)
		st, ok := tt.Underlying().(*types.Struct)
		if !ok || idx[i] >= st.NumFields() {
			return ""
		}
		t = st.Field(idx[i]).Type()
	}
	t = derefType(t)
	if n, ok := t.(*types.Named); ok && n.Obj() != nil && n.Obj().Pkg() != nil {
		return n.Obj().Pkg().Path() + "." + n.Obj().Name()
	}
	return ""
}

func derefType(t types.Type) types.Type {
	if p, ok := t.(*types.Pointer); ok {
		return p.Elem()
	}
	return t
}

// fieldParentName resolves the qualified name of the named struct type
// declaring field — "" when the declaring struct is anonymous (e.g.
// fields of a `[]struct{...}` literal element).
func (ix *Index) fieldParentName(field *types.Var) string {
	if ix.fieldOwners == nil {
		ix.fieldOwners = map[*types.Var]string{}
	}
	if v, ok := ix.fieldOwners[field]; ok {
		return v
	}
	owner := ""
	pp := ""
	if field.Pkg() != nil {
		pp = field.Pkg().Path()
	}
	for _, pkg := range ix.memberScope(pp) {
		if pkg.Types == nil {
			continue
		}
		scope := pkg.Types.Scope()
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			st, ok := tn.Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}
			for i := 0; i < st.NumFields(); i++ {
				// sameObject alone collides for same-named fields of
				// different structs in one package (shared types.Id):
				// the declaring field is the one at the same source
				// position — pointer equality covers same-load objects.
				sf := st.Field(i)
				if sf == field || (sameObject(sf, field) &&
					field.Pos().IsValid() && sf.Pos() == field.Pos()) {
					owner = pp + "." + name
				}
			}
		}
	}
	ix.fieldOwners[field] = owner
	return owner
}

// sameObject compares type objects by their package-qualified Id — pointer
// equality fails across separate packages.Load calls (dependency packages
// load on demand into the shared fileset with fresh object graphs).
func sameObject(a, b types.Object) bool {
	return a != nil && b != nil && a.Id() == b.Id()
}

func isHTTPRequest(t types.Type) bool {
	s := t.String()
	return strings.HasSuffix(s, "net/http.Request") || strings.HasSuffix(s, "*net/http.Request")
}

// classifyCall handles calls: known source functions, transformations, or
// opaque functions.
func (ix *Index) classifyCall(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr, depth int) (domain.DataOrigin, string) {
	return ix.classifyCallEval(pkg, enc, call, depth, -1, ix.topEval(pkg, enc))
}

// classifyCallEval classifies a call expression. Argument provenance is
// evaluated through evalArg — the caller-frame classify at top level or
// the callee-frame evalCalleeExpr when tracing function bodies — so the
// same source, passthrough and body-tracing rules apply in both frames. ridx is
// the bound result index for multi-value assignments (-1 = unspecified).
// classifyCallEval caps its explanation — the callee evaluator composes
// child whys upward recursively, so every boundary must bound its output
// or the strings grow exponentially down the call chain.
func (ix *Index) classifyCallEval(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr,
	depth int, ridx int, evalArg exprEval) (domain.DataOrigin, string) {
	o, w := ix.classifyCallEval0(pkg, enc, call, depth, ridx, evalArg)
	return o, capWhy(w)
}

// classifyCallEval0 evaluates a call expression's provenance through
// source semantics, the knowledge base, and callee-body tracing.
func (ix *Index) classifyCallEval0(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr,
	depth int, ridx int, evalArg exprEval) (domain.DataOrigin, string) {
	obj := calleeObject(pkg.TypesInfo, call.Fun)
	if ix.txBuf != nil {
		// Record the call as a transformation the traced value passes
		// through — observed along the trace regardless of its effect.
		name := callName(call.Fun)
		if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil {
			name = fn.Pkg().Path() + "." + fn.Name()
		}
		p := ix.fset.Position(call.Lparen)
		site := domain.CallSite{File: p.Filename, Line: p.Line, Callee: name}
		if enc != nil && enc.Name != nil {
			site.Function = enc.Name.Name
		}
		// One trace can visit millions of calls through the dep cone —
		// an unbounded, undeduped buffer is itself the memory bomb the
		// trace limits exist to prevent.
		if ix.txSeen == nil {
			ix.txSeen = map[domain.CallSite]bool{}
		}
		if !ix.txSeen[site] && len(*ix.txBuf) < maxTxBuf {
			ix.txSeen[site] = true
			*ix.txBuf = append(*ix.txBuf, site)
		}
	}
	if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil {
		key := fn.Pkg().Path() + "." + fn.Name()
		// DB/RPC source calls: result value is store- or service-provided.
		if ix.isDBFunc(fn) {
			return domain.OriginDatabase, fmt.Sprintf("result of %s", key)
		}
		if ix.isServiceCall(fn) {
			return domain.OriginInternalService, fmt.Sprintf("gRPC stub %s", key)
		}
		// Outbound HTTP calls: an internal/configured endpoint is a service
		// boundary, a literal/explicit URL is plain external data.
		if o, why, ok := ix.httpClientOrigin(pkg, enc, fn, call, depth, evalArg); ok {
			return o, why
		}
		// Peer channel constructors and readers: a net.Conn/tls value and
		// bytes read through it are peer-controlled by construction.
		if peerSourceCallee(fn) {
			return domain.OriginExternalUntrusted, "peer channel " + key
		}
		if o, ok := ix.kb().SourceFuncs[key]; ok {
			return o, key
		}
		// Reflect value plumbing: TypeOf/Elem/Kind produce compile-time
		// type descriptors (constants); ValueOf/Interface/Convert move
		// the argument's value — the origin propagates.
		if fn.Pkg().Path() == "reflect" {
			switch fn.Name() {
			case "TypeOf":
				return domain.OriginConstant, "reflect.TypeOf type descriptor"
			case "PtrTo", "PointerTo", "SliceOf", "ArrayOf", "MapOf", "ChanOf",
				"FuncOf", "StructOf", "MakeMap", "MakeMapWithSize", "MakeSlice",
				"MakeChan", "New", "Zero":
				// Type constructors yield descriptors; fresh-container
				// constructors allocate zero values — neither carries
				// input data. NewAt is excluded: it wraps a raw unsafe
				// pointer whose writes are untraceable; Append/Copy/
				// Swapper move boxed values — they propagate via Value.
				return domain.OriginConstant, "reflect." + fn.Name() + " (metadata/fresh value)"
			case "Indirect":
				if len(call.Args) == 1 {
					return evalArg(call.Args[0], depth+1)
				}
				return domain.OriginUnknown, "reflect.Indirect argument unavailable"
			case "ValueOf":
				if len(call.Args) == 1 {
					return evalArg(call.Args[0], depth)
				}
				return domain.OriginConstant, "reflect.ValueOf"
			}
			if sig, ok2 := fn.Type().(*types.Signature); ok2 && sig.Recv() != nil {
				rn := recvTypeName(sig.Recv().Type())
				switch rn {
				case "Type":
					// reflect.Type queries read type metadata — build-time
					// constants, not data.
					return domain.OriginConstant, "reflect.Type." + fn.Name()
				case "StructTag":
					// Tag accessors return a substring of the tag —
					// the receiver's provenance propagates.
					if sel, ok3 := call.Fun.(*ast.SelectorExpr); ok3 {
						o, why := evalArg(sel.X, depth)
						return o, "reflect.StructTag." + fn.Name() + " of " + why
					}
				case "Value":
					// reflect.Value accessors relocate the boxed value.
					if sel, ok3 := call.Fun.(*ast.SelectorExpr); ok3 {
						o, why := evalArg(sel.X, depth)
						return o, "reflect.Value." + fn.Name() + " of " + why
					}
				}
			}
		}
		// Carrier constructors/accessors: the result derives from one
		// input — io.ReadAll(r), NewDecoder(r), NewRequest(m,url,b), or
		// accessor methods like scanner.Text()/b.String().
		if idx, ok := ix.kb().PassthroughFuncs[key]; ok && idx < len(call.Args) {
			o, why := evalArg(call.Args[idx], depth+1)
			return o, fmt.Sprintf("%s(%s)", key, why)
		}
		if ix.kb().ArgsMergeFuncs[key] {
			if callHasFunctionArg(pkg, call) {
				return domain.OriginUnknown, key + " invokes a callback with independent effects"
			}
			if strings.HasPrefix(key, "fmt.") && formatArgsMayCallUserCode(pkg, call) {
				return domain.OriginUnknown, key + " may invoke a formatting method with independent provenance"
			}
			// Variadic combinator: the result is built from every
			// argument (Sprintf format + operands, Join's error list).
			out := domain.OriginConstant
			var parts []string
			for _, a := range call.Args {
				o, w := evalArg(a, depth+1)
				parts = append(parts, w)
				out = mergeOrigin(out, o)
			}
			return out, fmt.Sprintf("%s args merged {%s}", key, strings.Join(parts, " | "))
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && ix.kb().PassthroughMethods[fn.Name()] {
			o, why := evalArg(sel.X, depth)
			return o, fmt.Sprintf("%s() on %s", fn.Name(), why)
		}
		if sig, ok2 := fn.Type().(*types.Signature); ok2 && sig.Recv() != nil && isHTTPRequest(sig.Recv().Type()) {
			return domain.OriginExternalUntrusted, "method on *http.Request"
		}
		if callHasFunctionArg(pkg, call) {
			return domain.OriginUnknown, fmt.Sprintf("opaque callback passed to %s", key)
		}
		// Not a named source: trace into the callee body — if its result is
		// derived purely from parameters/constants, the caller's argument
		// origins propagate. Unresolvable bodies stay UNKNOWN.
		if o, why, ok := ix.traceCallee(fn, call, evalArg, depth, ridx); ok {
			return o, why
		}
		return domain.OriginUnknown, fmt.Sprintf("opaque call %s", key)
	}
	// Builtins and type expressions carry no input: `new(T)`/`make(T)`/
	// `T(x)` produce a fresh value or reinterpret args — for conversions
	// the result propagates the origin of the converted value.
	if tv, ok := pkg.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
		if len(call.Args) == 1 {
			return evalArg(call.Args[0], depth)
		}
		return domain.OriginConstant, "type conversion"
	}
	if b, ok := obj.(*types.Builtin); ok {
		switch b.Name() {
		case "new", "make", "print", "println":
			// Freshly allocated or derived-from-nothing values.
			return domain.OriginConstant, "builtin " + b.Name()
		case "recover":
			return domain.OriginUnknown, "builtin recover may return a dynamic panic value"
		case "len", "cap":
			if len(call.Args) == 1 {
				o, w := evalArg(call.Args[0], depth)
				return o, "len(" + w + ")"
			}
		case "append", "copy", "clear", "delete", "min", "max", "real", "imag", "complex":
			out := domain.OriginConstant
			var whys []string
			for _, a := range call.Args {
				o, w := evalArg(a, depth)
				whys = append(whys, w)
				out = mergeOrigin(out, o)
			}
			if len(whys) == 0 {
				return domain.OriginConstant, "builtin " + b.Name()
			}
			return out, "builtin " + b.Name() + " of " + strings.Join(whys, "; ")
		default:
			return domain.OriginConstant, "builtin " + b.Name()
		}
	}
	if len(call.Args) > 0 {
		return evalArg(call.Args[0], depth)
	}
	return domain.OriginUnknown, "unresolvable call"
}

func callHasFunctionArg(pkg *packages.Package, call *ast.CallExpr) bool {
	if pkg == nil || pkg.TypesInfo == nil {
		return len(call.Args) > 0
	}
	for _, arg := range call.Args {
		t := pkg.TypesInfo.TypeOf(arg)
		if t != nil {
			if _, ok := types.Unalias(t).Underlying().(*types.Signature); ok {
				return true
			}
		}
	}
	return false
}

func formatArgsMayCallUserCode(pkg *packages.Package, call *ast.CallExpr) bool {
	if pkg == nil || pkg.TypesInfo == nil {
		return true
	}
	seen := map[types.Type]bool{}
	for _, arg := range call.Args {
		if mayCallFormattingMethod(pkg.TypesInfo.TypeOf(arg), seen, 0) {
			return true
		}
	}
	return false
}

func mayCallFormattingMethod(t types.Type, seen map[types.Type]bool, depth int) bool {
	if t == nil || depth > 12 {
		return true
	}
	t = types.Unalias(t)
	if seen[t] {
		return false
	}
	seen[t] = true
	defer delete(seen, t)
	if _, ok := t.Underlying().(*types.Interface); ok {
		return true
	}
	for _, candidate := range []types.Type{t, types.NewPointer(t)} {
		ms := types.NewMethodSet(candidate)
		for _, name := range []string{"String", "Error", "GoString", "Format"} {
			if ms.Lookup(nil, name) != nil {
				return true
			}
		}
	}
	switch u := t.Underlying().(type) {
	case *types.Pointer:
		return mayCallFormattingMethod(u.Elem(), seen, depth+1)
	case *types.Array:
		return mayCallFormattingMethod(u.Elem(), seen, depth+1)
	case *types.Slice:
		return mayCallFormattingMethod(u.Elem(), seen, depth+1)
	case *types.Map:
		return mayCallFormattingMethod(u.Key(), seen, depth+1) || mayCallFormattingMethod(u.Elem(), seen, depth+1)
	case *types.Struct:
		for i := 0; i < u.NumFields(); i++ {
			if mayCallFormattingMethod(u.Field(i).Type(), seen, depth+1) {
				return true
			}
		}
	case *types.TypeParam:
		return true
	}
	return false
}

// peerSourceCallee reports whether fn produces or reads peer-controlled
// data: dial functions returning a connection, Accept on listeners, and
// Read-family methods on net/tls receivers. The peer boundary is the
// receiver type — a value of static type net.Conn carries wire bytes
// regardless of how deep inside a library it is materialized.
func peerSourceCallee(fn *types.Func) bool {
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		if n := recvNamed(sig.Recv().Type()); n != nil && n.Obj() != nil && n.Obj().Pkg() != nil {
			switch n.Obj().Pkg().Path() {
			case "net", "crypto/tls":
				switch fn.Name() {
				case "Read", "ReadFrom", "Accept", "AcceptTCP", "AcceptUnix":
					return true
				}
			}
		}
	}
	switch fn.Pkg().Path() {
	case "net":
		return strings.HasPrefix(fn.Name(), "Dial")
	case "crypto/tls":
		switch fn.Name() {
		case "Dial", "DialWithDialer", "Client", "Server":
			return true
		}
	}
	return false
}

// httpClientOrigin refines outbound HTTP calls: `http.Get(url)`,
// `client.Do(req)`. When the endpoint argument resolves to configuration
// the response is an INTERNAL_SERVICE value (service chosen by
// deployment); a literal or externally-derived URL stays
// EXTERNAL_UNTRUSTED. Returns ok=false for non-HTTP-client calls.
func (ix *Index) httpClientOrigin(pkg *packages.Package, enc *ast.FuncDecl, fn *types.Func, call *ast.CallExpr,
	depth int, evalArg exprEval) (domain.DataOrigin, string, bool) {
	pkgPath := fn.Pkg().Path()
	isClientMethod := false
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		if n := recvNamed(sig.Recv().Type()); n != nil && n.Obj() != nil &&
			n.Obj().Pkg() != nil && ix.kb().HTTPClientPkgs[n.Obj().Pkg().Path()] {
			isClientMethod = true
		}
	}
	isPkgFunc := ix.kb().HTTPClientPkgs[pkgPath] &&
		(fn.Name() == "Get" || fn.Name() == "Post" || fn.Name() == "Head" ||
			fn.Name() == "PostForm")
	if !isPkgFunc && !(isClientMethod && (fn.Name() == "Get" || fn.Name() == "Post" ||
		fn.Name() == "Do" || fn.Name() == "Head" || fn.Name() == "PostForm")) {
		return "", "", false
	}
	// Endpoint argument: url string for Get/Post, *http.Request for Do.
	var endpoint ast.Expr
	if len(call.Args) > 0 {
		endpoint = call.Args[0]
	}
	if endpoint != nil && depth < ix.hops() {
		if o, _ := evalArg(endpoint, depth+1); o == domain.OriginConfiguration || o == domain.OriginDatabase {
			return domain.OriginInternalService,
				fmt.Sprintf("http %s to configured endpoint", fn.Name()), true
		}
	}
	if ix.hasAuthMarkers(enc) {
		return domain.OriginExternalAuthenticated,
			fmt.Sprintf("http %s via authenticated client", fn.Name()), true
	}
	return domain.OriginExternalUntrusted, fmt.Sprintf("http %s response body", fn.Name()), true
}

// hasAuthMarkers reports whether the enclosing function attaches
// credentials somewhere in its body: an "Authorization" header literal or
// a call to a credential-attaching helper (kb().AuthCallNames).
// Heuristic — it notes that a peer is *probably* authenticated, never
// that input is safe.
func (ix *Index) hasAuthMarkers(enc *ast.FuncDecl) bool {
	if enc == nil || enc.Body == nil {
		return false
	}
	found := false
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch x := n.(type) {
		case *ast.BasicLit:
			if x.Kind == token.STRING &&
				strings.EqualFold(strings.Trim(x.Value, `"`), "authorization") {
				found = true
			}
		case *ast.CallExpr:
			if ix.kb().AuthCallNames[callName(x.Fun)] {
				found = true
			}
		}
		return !found
	})
	return found
}

// callName returns the final identifier of a callee expression —
// `x.SetBasicAuth` → "SetBasicAuth", `f` → "f".
func callName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

// exprEval evaluates an expression in the frame where it syntactically
// lives (caller argument at the top level, or a callee body during
// forward tracing).
type exprEval func(e ast.Expr, depth int) (domain.DataOrigin, string)

// topEval adapts classify for call-site arguments in the caller's frame.
func (ix *Index) topEval(pkg *packages.Package, enc *ast.FuncDecl) exprEval {
	return func(e ast.Expr, depth int) (domain.DataOrigin, string) {
		return ix.classify(pkg, enc, e, depth)
	}
}

// evalCallResult evaluates the origin of one result of a call bound by a
// multi-value assignment — `tok, err := d.Read()` picks result index 0,
// so error-branch returns cannot taint the payload origin. The full call
// classifier runs (source semantics, KB entries, body trace): only the
// per-index split inside traceCallee differs from a plain call.
func (ix *Index) evalCallResult(dp *packages.Package, decl *ast.FuncDecl, call *ast.CallExpr, ridx int, evalArg exprEval, depth int) (domain.DataOrigin, string) {
	return ix.classifyCallEval(dp, decl, call, depth, ridx, evalArg)
}

// traceCallee attempts to prove that fn's result derives only from its
// parameters and constants. Returns ok=false when the body is unavailable,
// contaminated by external sources, or too complex to resolve — the caller
// then yields UNKNOWN rather than guessing. ridx selects one result
// position of a multi-value signature (-1 merges every return).
func (ix *Index) traceCallee(fn *types.Func, call *ast.CallExpr, evalArg exprEval, depth int, ridx int) (domain.DataOrigin, string, bool) {
	if depth >= ix.hops() {
		return "", "", false
	}
	// Recursive callee chains (f → … → f) are exponential without a
	// guard: each re-entry re-scans the whole body. A function already
	// on the trace stack yields nothing, so the caller leaves that call
	// UNKNOWN instead of treating its explicit arguments as exhaustive.
	if ix.calleeTraceIn == nil {
		ix.calleeTraceIn = map[string]bool{}
	}
	fnKey := fn.Pkg().Path() + "." + fn.Name()
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		fnKey += "." + recvTypeName(sig.Recv().Type())
	}
	if ix.calleeTraceIn[fnKey] {
		return "", "", false
	}
	ix.calleeTraceIn[fnKey] = true
	defer delete(ix.calleeTraceIn, fnKey)
	decl, dp := ix.funcDecl(fn)
	if decl == nil || decl.Body == nil || dp == nil || dp.TypesInfo == nil {
		return "", "", false
	}
	if ix.bodyContaminated(dp, decl) {
		return "", "", false
	}
	// map callee parameter name -> index into the call's argument list
	paramIdx := map[string]int{}
	variadicIdx := -1
	i := 0
	if decl.Type.Params != nil {
		for _, f := range decl.Type.Params.List {
			if _, isEll := f.Type.(*ast.Ellipsis); isEll && len(f.Names) > 0 {
				variadicIdx = i + len(f.Names) - 1
			}
			for _, n := range f.Names {
				paramIdx[n.Name] = i
				i++
			}
		}
	}
	// A named receiver binds to the call's receiver expression the same
	// way parameters bind to arguments — without it `ret := *d` inside
	// Clone-style bodies leaves `d` unresolvable.
	var recvName string
	if decl.Recv != nil {
		for _, f := range decl.Recv.List {
			for _, n := range f.Names {
				recvName = n.Name
			}
		}
	}
	argAt := func(name string) ([]ast.Expr, bool) {
		if name != "" && name == recvName {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				return []ast.Expr{sel.X}, true
			}
			return nil, false
		}
		j, ok := paramIdx[name]
		if !ok {
			return nil, false
		}
		if j == variadicIdx {
			// A variadic parameter consumes all remaining arguments —
			// including zero, which binds an empty (constant) slice.
			if j < len(call.Args) {
				return call.Args[j:], true
			}
			return nil, true
		}
		if j >= len(call.Args) {
			return nil, false
		}
		return []ast.Expr{call.Args[j]}, true
	}
	arity := -1
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Results() != nil {
		arity = sig.Results().Len()
	}
	var out domain.DataOrigin
	nret := 0
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		rs, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		pickable := ridx >= 0 && len(rs.Results) == arity && arity > 1
		for i, re := range rs.Results {
			// Only the requested result index contributes: error-branch
			// expressions bound to sibling slots stay out of the merge.
			// Tuple-forwarding returns (`return f()`) cannot be split —
			// the whole expression merges, staying conservative.
			if pickable && i != ridx {
				continue
			}
			nret++
			o, _ := ix.evalCalleeExpr(dp, decl, re, argAt, evalArg, depth)
			out = mergeOrigin(out, o)
		}
		return true
	})
	if nret == 0 || out == "" {
		return "", "", false
	}
	return out, fmt.Sprintf("traced %s.%s body", fn.Pkg().Path(), fn.Name()), true
}

// evalCalleeExpr classifies an expression inside a callee body: parameters
// resolve through argAt+evalArg (the caller's frame), locals through their
// dominating assignment, everything else conservatively UNKNOWN.
// maxEvalBudget is the default work bound for callee-frame expression
// evaluation — large modules like protobuf would otherwise keep the
// classification running for minutes on var-origin merges.
const maxEvalBudget = 300000

// budgeted reports whether classification work may proceed: counts down
// the session budget; once exhausted it stays exhausted — the origin
// degrades to UNKNOWN rather than resuming with a negative budget.
func (ix *Index) budgeted() bool {
	if ix.evalBudget < 0 {
		return false
	}
	if ix.evalBudget == 0 {
		return true // 0 = unlimited outside bounded sessions
	}
	ix.evalBudget--
	if ix.evalBudget == 0 {
		ix.evalBudget = -1
	}
	return true
}

// evalCalleeExpr caps its explanation like classifyCallEval — the two
// recurse through each other, so either boundary left uncapped lets
// composed whys grow exponentially with call-chain depth.
func (ix *Index) evalCalleeExpr(dp *packages.Package, decl *ast.FuncDecl, e ast.Expr,
	argAt func(string) ([]ast.Expr, bool), evalArg exprEval, depth int) (domain.DataOrigin, string) {
	o, w := ix.evalCalleeExpr0(dp, decl, e, argAt, evalArg, depth)
	return o, capWhy(w)
}

func (ix *Index) evalCalleeExpr0(dp *packages.Package, decl *ast.FuncDecl, e ast.Expr,
	argAt func(string) ([]ast.Expr, bool), evalArg exprEval, depth int) (domain.DataOrigin, string) {
	if !ix.budgeted() {
		return domain.OriginUnknown, "evaluation budget exhausted"
	}
	if !ix.enterExpr() {
		return domain.OriginUnknown, "expression depth exceeded"
	}
	defer ix.leaveExpr()

	// Type expressions (`map[K]V`, `[]T`) carry metadata, not data.
	if tv, ok := dp.TypesInfo.Types[e]; ok && tv.IsType() {
		return domain.OriginConstant, "type expression"
	}

	switch v := e.(type) {
	case *ast.BasicLit:
		return domain.OriginConstant, "literal"
	case *ast.CompositeLit:
		out := domain.OriginConstant
		for _, el := range v.Elts {
			if kv, ok := el.(*ast.KeyValueExpr); ok {
				el = kv.Value
			}
			o, _ := ix.evalCalleeExpr(dp, decl, el, argAt, evalArg, depth)
			out = mergeOrigin(out, o)
		}
		return out, "composite literal"
	case *ast.Ident:
		switch v.Name {
		case "nil", "true", "false", "iota":
			return domain.OriginConstant, "builtin"
		}
		if args, ok := argAt(v.Name); ok {
			out := domain.OriginConstant
			var parts []string
			for _, arg := range args {
				o, w := evalArg(arg, depth+1)
				parts = append(parts, w)
				out = mergeOrigin(out, o)
			}
			if len(parts) == 0 {
				return domain.OriginConstant, "variadic param " + v.Name + " <- empty"
			}
			return out, "param " + v.Name + " <- " + strings.Join(parts, " | ")
		}
		obj := dp.TypesInfo.ObjectOf(v)
		if _, isConst := obj.(*types.Const); isConst {
			return domain.OriginConstant, "named constant " + v.Name
		}
		if vr, isVar := obj.(*types.Var); isVar {
			if init := findVarInit(dp, vr); init != nil {
				o, w := ix.classify(dp, nil, init, depth+1)
				return o, "package-level " + v.Name + " <- " + w
			}
		}
		rhsList := ix.assigns(decl, obj)
		rhsList = append(rhsList, elemWriteRHSs(decl, obj)...)
		// Same cycle guard as classifyIdent: x = x + t re-enters the
		// same var's assignments — the accumulated value keeps the
		// origins already merged, the self-reference adds nothing.
		// calleeEvalSeen is lazily owned by this frame so the guard
		// holds on any entry path, not only inside Trace*.
		if ix.calleeEvalSeen == nil {
			ix.calleeEvalSeen = map[types.Object]bool{}
		}
		if ix.calleeEvalSeen[obj] {
			// Self-referential writes contribute no new origin — the
			// accumulated value keeps the origins already merged.
			return domain.OriginConstant, "self-reference"
		}
		ix.calleeEvalSeen[obj] = true
		defer delete(ix.calleeEvalSeen, obj)
		var merged domain.DataOrigin
		var whys []string
		for _, rhs := range rhsList {
			o, w := ix.evalCalleeExpr(dp, decl, rhs, argAt, evalArg, depth)
			merged = mergeOrigin(merged, o)
			whys = append(whys, w)
		}
		// Call-populated locals inside the callee: io.ReadFull(r, buf),
		// binary.Read(r, _, &size), buf.Write(x) — same rules as the
		// caller-frame scan, evaluated in the callee's frame.
		inner := func(e ast.Expr, d int) (domain.DataOrigin, string) {
			return ix.evalCalleeExpr(dp, decl, e, argAt, evalArg, d)
		}
		if o, w, ok := ix.populatedByCall(dp, decl, obj, depth, inner); ok {
			merged = mergeOrigin(merged, o)
			whys = append(whys, w)
		}
		// Unsafe pointer stores `*(*T)(unsafe.Pointer(&v)) = e` populate
		// the variable through a dereference — stored-value origin applies.
		if rhsList := derefWriteRHSs(decl, obj); len(rhsList) > 0 {
			for _, rhs := range rhsList {
				o, w := ix.evalCalleeExpr(dp, decl, rhs, argAt, evalArg, depth)
				merged = mergeOrigin(merged, o)
				whys = append(whys, "deref-write: "+w)
			}
		}
		if rhs, ridx := multiAssignRHS(decl, obj, dp.TypesInfo); rhs != nil {
			var o domain.DataOrigin
			var w string
			if call, isCall := rhs.(*ast.CallExpr); isCall {
				o, w = ix.evalCallResult(dp, decl, call, ridx, inner, depth)
			} else {
				o, w = ix.evalCalleeExpr(dp, decl, rhs, argAt, evalArg, depth)
			}
			merged = mergeOrigin(merged, o)
			whys = append(whys, "multi-assign: "+w)
		}
		if merged != "" {
			return merged, "local " + v.Name + " <- {" + strings.Join(whys, " | ") + "}"
		}
		// `switch v := e.(type)` binds v to e asserted — the guard
		// expression carries the origin.
		if g := typeSwitchBoundExpr(decl, obj); g != nil {
			o, w := ix.evalCalleeExpr(dp, decl, g, argAt, evalArg, depth)
			return o, "type-switch over " + w
		}
		// FuncLit parameters are fed by the call consuming the literal —
		// they inherit the hosting call's receiver/argument origins.
		if host := litHostCall(decl, obj); host != nil {
			o, w := litHostOrigin(host, inner, depth)
			return o, "callback " + v.Name + " <- " + w
		}
		// Named result accumulated only through self-writes (n++,
		// n += e): the counter/accumulator derives from itself plus the
		// compound-assign operands — merge those, no external origin.
		if acc, ok := selfAccumWrites(decl, obj); ok {
			out := domain.OriginConstant
			for _, rhs := range acc {
				o, _ := ix.evalCalleeExpr(dp, decl, rhs, argAt, evalArg, depth)
				out = mergeOrigin(out, o)
			}
			return out, "accumulator " + v.Name
		}
		if rx := rangeBoundExpr(dp, decl, obj); rx != nil {
			o, w := ix.evalCalleeExpr(dp, decl, rx, argAt, evalArg, depth)
			return o, "range over " + w
		}
		// Static code references carry no runtime data; package-level
		// vars resolve through their initializer.
		if _, isPkg := obj.(*types.PkgName); isPkg {
			return domain.OriginConstant, "package qualifier " + v.Name
		}
		if _, isFn := obj.(*types.Func); isFn {
			return domain.OriginConstant, "function reference " + v.Name
		}
		if vr, isVar := obj.(*types.Var); isVar {
			if init := findVarInit(dp, vr); init != nil {
				o, w := ix.evalCalleeExpr(dp, decl, init, argAt, evalArg, depth+1)
				return o, "package-level " + v.Name + " <- " + w
			}
		}
		return domain.OriginUnknown, "unresolvable ident " + v.Name
	case *ast.SelectorExpr:
		// Field access propagates the enclosing value's origin
		// (field.Type, info.Num); package-qualified selections resolve
		// through the object — consts are constant, vars take their
		// initializer's origin.
		if _, isSel := dp.TypesInfo.Selections[v]; !isSel {
			if obj := dp.TypesInfo.ObjectOf(v.Sel); obj != nil {
				if _, isConst := obj.(*types.Const); isConst {
					return domain.OriginConstant, "named constant " + v.Sel.Name
				}
				if vr, isVar := obj.(*types.Var); isVar {
					if init := findVarInit(dp, vr); init != nil {
						o, w := ix.classify(dp, nil, init, depth+1)
						return o, "package-level " + v.Sel.Name + " <- " + w
					}
				}
			}
		}
		return ix.evalCalleeExpr(dp, decl, v.X, argAt, evalArg, depth)
	case *ast.FuncLit:
		return domain.OriginConstant, "function literal"
	case *ast.ParenExpr:
		return ix.evalCalleeExpr(dp, decl, v.X, argAt, evalArg, depth)
	case *ast.UnaryExpr:
		if v.Op == token.ARROW {
			return domain.OriginUnknown, "channel receive: send sites not inventoried"
		}
		return ix.evalCalleeExpr(dp, decl, v.X, argAt, evalArg, depth)
	case *ast.StarExpr:
		return ix.evalCalleeExpr(dp, decl, v.X, argAt, evalArg, depth)
	case *ast.TypeAssertExpr:
		return ix.evalCalleeExpr(dp, decl, v.X, argAt, evalArg, depth)
	case *ast.BinaryExpr:
		xo, _ := ix.evalCalleeExpr(dp, decl, v.X, argAt, evalArg, depth)
		yo, _ := ix.evalCalleeExpr(dp, decl, v.Y, argAt, evalArg, depth)
		return mergeOrigin(xo, yo), "binary expr"
	case *ast.IndexExpr, *ast.IndexListExpr, *ast.SliceExpr:
		return ix.evalCalleeExpr(dp, decl, childExpr(v), argAt, evalArg, depth)
	case *ast.CallExpr:
		obj := calleeObject(dp.TypesInfo, v.Fun)
		if _, isType := obj.(*types.TypeName); isType && len(v.Args) == 1 {
			return ix.evalCalleeExpr(dp, decl, v.Args[0], argAt, evalArg, depth)
		}
		// Delegate to the shared call classifier so callee bodies get the
		// same source/passthrough/reflect/callback rules as top-level
		// call sites — without them stdlib helpers (strings.Split,
		// fmt.Sprintf, reflect.Value accessors) trace into unresolvable
		// runtime internals and pollute the merged origin with UNKNOWN.
		inner := func(a ast.Expr, d int) (domain.DataOrigin, string) {
			return ix.evalCalleeExpr(dp, decl, a, argAt, evalArg, d)
		}
		return ix.classifyCallEval(dp, decl, v, depth, -1, inner)
	}
	return domain.OriginUnknown, fmt.Sprintf("unsupported callee expr %T", e)
}

// bodyContaminated reports whether the callee body reads any external data
// source itself. If it does, we cannot prove the output is input-derived,
// so the result must stay UNKNOWN.
func (ix *Index) bodyContaminated(dp *packages.Package, decl *ast.FuncDecl) bool {
	bad := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			if obj := dp.TypesInfo.ObjectOf(v.Sel); obj != nil {
				if b, ok := obj.(*types.Var); ok && b.Pkg() != nil &&
					b.Pkg().Path() == "os" && b.Name() == "Args" {
					bad = true
				}
			}
			if sel, ok := dp.TypesInfo.Selections[v]; ok && isHTTPRequest(sel.Recv()) {
				bad = true
			}
		case *ast.CallExpr:
			if fn, ok := calleeObject(dp.TypesInfo, v.Fun).(*types.Func); ok && fn.Pkg() != nil {
				if o, ok := ix.kb().SourceFuncs[fn.Pkg().Path()+"."+fn.Name()]; ok &&
					o != domain.OriginConstant {
					bad = true
				}
			}
		}
		return !bad
	})
	return bad
}

// funcDeclResult is the memoized outcome of a funcDecl lookup.
type funcDeclResult struct {
	decl *ast.FuncDecl
	pkg  *packages.Package
}

// funcDecl finds the FuncDecl and package for a function object — product
// package first, then a dependency loaded on demand.
func (ix *Index) funcDecl(fn *types.Func) (*ast.FuncDecl, *packages.Package) {
	var recvName0 string
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		recvName0 = recvTypeName(sig.Recv().Type())
	}
	cacheKey := fn.Pkg().Path() + "." + recvName0 + "." + fn.Name()
	if ix.funcDeclCache != nil {
		if r, ok := ix.funcDeclCache[cacheKey]; ok {
			return r.decl, r.pkg
		}
	}
	decl, dp := ix.funcDecl0(fn)
	if ix.funcDeclCache != nil && len(ix.funcDeclCache) < maxClassifyCache {
		ix.funcDeclCache[cacheKey] = funcDeclResult{decl, dp}
	}
	return decl, dp
}

func (ix *Index) funcDecl0(fn *types.Func) (*ast.FuncDecl, *packages.Package) {
	find := func(pkg *packages.Package) *ast.FuncDecl {
		var recvName string
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			recvName = recvTypeName(sig.Recv().Type())
		}
		for _, f := range pkg.Syntax {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Name == nil || fd.Name.Name != fn.Name() {
					continue
				}
				// types.Func objects differ between loads; match by name +
				// receiver type instead of object identity.
				if recvName == "" {
					if fd.Recv == nil || len(fd.Recv.List) == 0 {
						return fd
					}
					continue
				}
				if fd.Recv == nil || len(fd.Recv.List) == 0 {
					continue
				}
				t := pkg.TypesInfo.TypeOf(fd.Recv.List[0].Type)
				if t != nil && recvTypeName(t) == recvName {
					return fd
				}
			}
		}
		return nil
	}
	for _, pkg := range ix.pkgs {
		if pkg.PkgPath == fn.Pkg().Path() {
			if d := find(pkg); d != nil {
				return d, pkg
			}
		}
	}
	extra, err := ix.loadExtra(ix.ctxOr(nil), fn.Pkg().Path())
	if err != nil {
		return nil, nil
	}
	for _, pkg := range extra {
		if pkg.PkgPath == fn.Pkg().Path() {
			if d := find(pkg); d != nil {
				return d, pkg
			}
		}
	}
	return nil, nil
}

// TraceAllArguments classifies every argument of the call site — used when
// the attacker-controlled parameter index is not known in advance.
// TraceAllArgumentsBound is TraceAllArguments with an explicit
// caller-climb budget — used by negative verification's re-trace.
func (ix *Index) TraceAllArgumentsBound(ctx context.Context, site domain.CallSite, hops int) ([]domain.DataFlow, []domain.Evidence, error) {
	ix.mu.Lock()
	ix.hopLimit = hops
	ix.mu.Unlock()
	defer func() {
		ix.mu.Lock()
		ix.hopLimit = 0
		ix.mu.Unlock()
	}()
	return ix.TraceAllArguments(ctx, site)
}

func (ix *Index) TraceAllArguments(ctx context.Context, site domain.CallSite) ([]domain.DataFlow, []domain.Evidence, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	call, enc, pkg, err := ix.callAt(site)
	if err != nil {
		return nil, nil, err
	}
	var flows []domain.DataFlow
	var ev []domain.Evidence
	src, _ := ix.nodeSource(call)
	ev = append(ev, domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityStructural,
		Source:  "ast argument trace",
		Tool:    "vuln-analyzer/goanalysis",
		File:    site.File,
		Content: src,
	})
	for i := range call.Args {
		var tx []domain.CallSite
		ix.txBuf = &tx
		ix.traceSeen = map[types.Object]bool{}
		ix.paramSeen = map[string]bool{}
		ix.paramCache = map[string]classifyResult{}
		ix.classifyCache = map[classifyKey]classifyResult{}
		ix.evalBudget = maxEvalBudget
		origin, why := ix.classify(pkg, enc, call.Args[i], 0)
		ix.txBuf = nil
		ix.txSeen = nil
		ix.traceSeen = nil
		ix.paramSeen = nil
		ix.paramCache = nil
		ix.classifyCache = nil
		ix.evalBudget = 0
		flows = append(flows, domain.DataFlow{
			Arg:             i,
			Sink:            site,
			Source:          site,
			Origin:          origin,
			PayloadUnproven: payloadUnprovenParameter(pkg, call, i),
			Transformations: dedupSites(tx),
			Summary:         fmt.Sprintf("arg%d: %s", i, why),
		})
	}
	return flows, ev, nil
}

func payloadUnprovenParameter(pkg *packages.Package, call *ast.CallExpr, argIndex int) bool {
	if pkg == nil || pkg.TypesInfo == nil || call == nil || argIndex < 0 {
		return false
	}
	calleeType := pkg.TypesInfo.TypeOf(call.Fun)
	if calleeType == nil {
		return false
	}
	sig, _ := types.Unalias(calleeType).Underlying().(*types.Signature)
	if sig == nil || sig.Params() == nil {
		return false
	}
	params := sig.Params()
	if sig.Variadic() && params.Len() > 0 && argIndex >= params.Len()-1 {
		variadic, _ := types.Unalias(params.At(params.Len() - 1).Type()).Underlying().(*types.Slice)
		return variadic != nil && writerOnlyType(variadic.Elem())
	}
	if argIndex >= params.Len() {
		return false
	}
	return writerOnlyType(params.At(argIndex).Type())
}

func writerOnlyType(t types.Type) bool {
	if t == nil {
		return false
	}
	methods := types.NewMethodSet(types.Unalias(t))
	write := methods.Lookup(nil, "Write")
	if write == nil {
		return false
	}
	sig, _ := types.Unalias(write.Obj().Type()).Underlying().(*types.Signature)
	if !canonicalByteIO(sig) {
		return false
	}
	read := methods.Lookup(nil, "Read")
	if read == nil {
		return true
	}
	readSig, _ := types.Unalias(read.Obj().Type()).Underlying().(*types.Signature)
	return !canonicalByteIO(readSig)
}

func canonicalByteIO(sig *types.Signature) bool {
	if sig == nil || sig.Variadic() || sig.Params().Len() != 1 || sig.Results().Len() != 2 {
		return false
	}
	errorType := types.Universe.Lookup("error").Type()
	return types.Identical(types.Unalias(sig.Params().At(0).Type()),
		types.NewSlice(types.Typ[types.Byte])) &&
		types.Identical(types.Unalias(sig.Results().At(0).Type()), types.Typ[types.Int]) &&
		types.Identical(types.Unalias(sig.Results().At(1).Type()), types.Unalias(errorType))
}

// InputParamIndex heuristically selects the parameter index most likely to
// carry attacker-controlled data, from the callee's signature: request-like
// and reader types win over plain data types. Returns -1 when nothing
// looks like input — callers must treat that as UNKNOWN, never guess.
func (ix *Index) InputParamIndex(ref domain.SymbolRef) (int, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cs, err := ix.findSymbol(ix.ctxOr(nil), ref)
	if err != nil {
		return -1, err
	}
	decl, dp, err := ix.funcDeclAt(cs, ref)
	if err != nil || decl == nil || decl.Type.Params == nil {
		return -1, fmt.Errorf("signature for %s.%s unavailable", ref.Package, ref.Symbol)
	}
	best, bestScore := -1, 0
	i := 0
	for _, f := range decl.Type.Params.List {
		tstr := ""
		if dp != nil && dp.TypesInfo != nil {
			if t := dp.TypesInfo.TypeOf(f.Type); t != nil {
				tstr = t.String()
			}
		}
		for range f.Names {
			if s := inputScore(tstr); s > bestScore {
				best, bestScore = i, s
			}
			i++
		}
	}
	return best, nil
}

// funcDeclAt locates the FuncDecl for a symbol — reusing the definition
// position when available.
func (ix *Index) funcDeclAt(cs *domain.CallSite, ref domain.SymbolRef) (*ast.FuncDecl, *packages.Package, error) {
	pkgs := ix.pkgs
	extra, err := ix.loadExtra(ix.ctxOr(nil), ref.Package)
	if err == nil {
		pkgs = append(append([]*packages.Package{}, ix.pkgs...), extra...)
	}
	_, wantName := splitSymbol(ref.Symbol)
	for _, pkg := range pkgs {
		if pkg.PkgPath != ref.Package {
			continue
		}
		for _, f := range pkg.Syntax {
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Name == nil || fd.Name.Name != wantName {
					continue
				}
				pos := ix.fset.Position(fd.Pos())
				if pos.Filename == cs.File {
					return fd, pkg, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("func decl not found")
}

// inputScore ranks parameter types by how plausibly they carry attacker
// input. Ordering matters: request types outrank readers, readers outrank
// plain strings/bytes.
func inputScore(t string) int {
	switch {
	case strings.Contains(t, "net/http.Request"):
		return 5
	case strings.Contains(t, "io.ReadCloser"), strings.Contains(t, "io.Reader"),
		strings.Contains(t, "http.ResponseWriter"):
		if strings.Contains(t, "ResponseWriter") {
			return -1 // output, not input
		}
		return 4
	case t == "[]byte", t == "string", t == "[]rune", strings.HasSuffix(t, "io.Buffer"):
		return 3
	case strings.HasPrefix(t, "[]"):
		return 2
	case strings.Contains(t, "io.Writer"):
		return -1
	}
	return 0
}

// traceParam resolves an argument bound to an enclosing function parameter by
// looking at the callers of that function (one hop).
func (ix *Index) traceParam(pkg *packages.Package, enc *ast.FuncDecl, v *types.Var, depth int) (domain.DataOrigin, string) {
	// find which parameter index this is
	paramIdx := paramIndexOf(enc, v.Name())
	if paramIdx < 0 {
		return domain.OriginUnknown, "parameter index not found"
	}
	// Recursive self-calls re-feed the same parameter slot — the recursive
	// edge carries no new origin, so an in-progress resolution of this
	// (function, slot) contributes nothing to the merge. Checked before
	// the depth bound so cycles terminate even deep in the chain.
	slot := fmt.Sprintf("%s|%s|arg%d", pkg.PkgPath, funcSymbolRef(pkg, enc).Symbol, paramIdx)
	if ix.paramCache != nil {
		if r, ok := ix.paramCache[slot]; ok {
			return r.origin, r.why
		}
	}
	if ix.paramSeen != nil && ix.paramSeen[slot] {
		return domain.OriginConstant, fmt.Sprintf("param %s: self-reference", v.Name())
	}
	if depth >= ix.hops() || enc == nil || enc.Name == nil {
		return domain.OriginUnknown, fmt.Sprintf("parameter %s of %s: caller tracing depth exceeded (depth=%d)", v.Name(), enc.Name, depth)
	}
	if ix.paramSeen != nil {
		ix.paramSeen[slot] = true
		defer delete(ix.paramSeen, slot)
	}
	// callers of enclosing function — product scope for product code; for
	// dependency functions the dep package plus product roots (peer-driven
	// internals are invoked entirely inside the dep).
	var encRef domain.SymbolRef
	if pkg.Types != nil {
		encRef = funcSymbolRef(pkg, enc)
	}
	refs := ix.callersOf(pkg, encRef)
	if len(refs) == 0 {
		return domain.OriginUnknown, fmt.Sprintf("no static callers of %s found", enc.Name.Name)
	}
	var merged domain.DataOrigin
	var whys []string
	onPath := 0
	for _, r := range refs {
		if !ix.callerOnPath(r) || !ix.callerReachable(r.pkg, r.enclosing) {
			continue
		}
		if r.possible {
			// An unresolved func-value dispatch may feed this slot —
			// counted as an unknown writer, its args are not traced.
			onPath++
			merged = mergeOrigin(merged, domain.OriginUnknown)
			whys = append(whys, fmt.Sprintf("%s:%d unresolved func-value dispatch", r.Site.File, r.Site.Line))
			continue
		}
		if paramIdx >= len(r.call.Args) {
			continue
		}
		onPath++
		o, w := ix.classify(r.pkg, r.enclosing, r.call.Args[paramIdx], depth+1)
		whys = append(whys, fmt.Sprintf("%s:%d %s", r.Site.File, r.Site.Line, w))
		merged = mergeOrigin(merged, o)
	}
	if merged == "" {
		return domain.OriginUnknown, "no caller arguments resolvable"
	}
	why := fmt.Sprintf("param %s via %d caller(s): %s", v.Name(), onPath, capWhy(strings.Join(whys, "; ")))
	if ix.paramCache != nil && len(ix.paramCache) < maxAuxCache {
		ix.paramCache[slot] = classifyResult{origin: merged, why: why}
	}
	return merged, why
}

// sameType reports whether two types denote the same type even when they
// come from separately loaded package instances: extras eviction and
// multi-pattern loads can type-check the same package more than once,
// after which types.Identical fails on *types.Named values belonging to
// different type-checker runs. Named types therefore also compare by
// package path and object name — the stable identity a type has across
// reloads of the same module version. Pointer depth is preserved: *T is
// not T.
func sameType(a, b types.Type) bool {
	if types.Identical(a, b) {
		return true
	}
	if pa, ok := a.(*types.Pointer); ok {
		pb, ok2 := b.(*types.Pointer)
		return ok2 && sameType(pa.Elem(), pb.Elem())
	}
	if _, ok := b.(*types.Pointer); ok {
		return false
	}
	na, _ := a.(*types.Named)
	nb, _ := b.(*types.Named)
	if na == nil || nb == nil {
		return false
	}
	oa, ob := na.Obj(), nb.Obj()
	if oa == nil || ob == nil || oa.Name() != ob.Name() {
		return false
	}
	pa, pb := oa.Pkg(), ob.Pkg()
	if pa == nil || pb == nil {
		return pa == pb
	}
	return pa.Path() == pb.Path()
}

// isReceiver reports whether v is the method receiver of enc —
// `func (v T) m(...)` binds v as a pseudo-parameter.
func isReceiver(enc *ast.FuncDecl, v *types.Var) bool {
	if enc == nil || enc.Recv == nil {
		return false
	}
	for _, f := range enc.Recv.List {
		for _, n := range f.Names {
			if n.Name == v.Name() {
				return true
			}
		}
	}
	return false
}

// traceReceiver resolves a method receiver's provenance by looking at the
// receiver expressions of the enclosing method's call sites — the mirror
// of traceParam for the receiver slot.
func (ix *Index) traceReceiver(pkg *packages.Package, enc *ast.FuncDecl, v *types.Var, depth int) (domain.DataOrigin, string) {
	slot := fmt.Sprintf("%s|%s|recv:%s", pkg.PkgPath, funcSymbolRef(pkg, enc).Symbol, v.Name())
	if ix.paramCache != nil {
		if r, ok := ix.paramCache[slot]; ok {
			return r.origin, r.why
		}
	}
	// A slot already on the trace stack contributes nothing new — check
	// before the depth bound so receiver cycles terminate even deep in
	// the chain.
	if ix.paramSeen != nil && ix.paramSeen[slot] {
		return domain.OriginConstant, fmt.Sprintf("receiver %s: self-reference", v.Name())
	}
	if depth >= ix.hops() || enc == nil || enc.Name == nil {
		return domain.OriginUnknown, fmt.Sprintf("receiver %s of %s: caller tracing depth exceeded (depth=%d)", v.Name(), enc.Name, depth)
	}
	if ix.paramSeen != nil {
		ix.paramSeen[slot] = true
		defer delete(ix.paramSeen, slot)
	}
	var encRef domain.SymbolRef
	if pkg.Types != nil {
		encRef = funcSymbolRef(pkg, enc)
	}
	refs := ix.callersOf(pkg, encRef)
	if len(refs) == 0 {
		return domain.OriginUnknown, fmt.Sprintf("no static callers of %s found", enc.Name.Name)
	}
	var merged domain.DataOrigin
	var whys []string
	onPath := 0
	for _, r := range refs {
		if !ix.callerOnPath(r) || !ix.callerReachable(r.pkg, r.enclosing) {
			continue
		}
		if r.possible {
			onPath++
			merged = mergeOrigin(merged, domain.OriginUnknown)
			whys = append(whys, fmt.Sprintf("%s:%d unresolved func-value dispatch", r.Site.File, r.Site.Line))
			continue
		}
		// The receiver expression: `d.M(...)` carries it in the selector;
		// a func-value call to a method expression (`unmarshal(d, m)`
		// where unmarshal = decoder.unmarshalAny) supplies it as arg0 —
		// identified by the called signature's first parameter matching
		// the receiver type.
		var rexpr ast.Expr
		if sel, ok := r.call.Fun.(*ast.SelectorExpr); ok {
			rexpr = sel.X
		} else if len(r.call.Args) > 0 {
			var sig *types.Signature
			if ft := r.pkg.TypesInfo.TypeOf(r.call.Fun); ft != nil {
				sig, _ = ft.Underlying().(*types.Signature)
			}
			if sig != nil && sig.Params().Len() > 0 &&
				sameType(sig.Params().At(0).Type(), v.Type()) {
				rexpr = r.call.Args[0]
			}
		}
		if rexpr == nil {
			continue
		}
		onPath++
		o, w := ix.classify(r.pkg, r.enclosing, rexpr, depth+1)
		whys = append(whys, fmt.Sprintf("%s:%d %s", r.Site.File, r.Site.Line, w))
		merged = mergeOrigin(merged, o)
	}
	if merged == "" {
		return domain.OriginUnknown, "no caller receiver resolvable"
	}
	why := fmt.Sprintf("receiver %s via %d caller(s): %s", v.Name(), onPath, capWhy(strings.Join(whys, "; ")))
	if ix.paramCache != nil && len(ix.paramCache) < maxAuxCache {
		ix.paramCache[slot] = classifyResult{origin: merged, why: why}
	}
	return merged, why
}

// callerReachable reports whether a caller's enclosing function can
// execute in this build at all. Product code always qualifies; a
// dependency-internal enclosing function is excluded only with positive
// unreachable evidence:
//
//   - its package is not linked into the program's import closure (dead
//     package, e.g. fuzz harnesses shipped in the module);
//   - it has no static callers and is a method that can only be invoked
//     through a reflect-driven API family whose call sites provably
//     cannot carry its receiver type (e.g. UnmarshalJSON reachable only
//     through encoding/json, which the build never feeds a proto type).
//
// Everything else stays reachable — the check is unknown-biased.
func (ix *Index) callerReachable(pkg *packages.Package, enc *ast.FuncDecl) bool {
	if pkg == nil || enc == nil || ix.isProductPath(pkg.PkgPath) {
		return true
	}
	// Dead-package exclusion comes before entry-point checks: a fuzz or
	// test entry in a package the program never imports cannot execute.
	if !ix.pkgLinked(pkg) {
		return false
	}
	if enc.Name != nil && (enc.Name.Name == "init" ||
		strings.HasPrefix(enc.Name.Name, "Test") || strings.HasPrefix(enc.Name.Name, "Benchmark") ||
		strings.HasPrefix(enc.Name.Name, "Fuzz") || strings.HasPrefix(enc.Name.Name, "Example")) {
		return true
	}
	if enc.Name == nil {
		return true
	}
	if len(ix.callersOf(pkg, funcSymbolRef(pkg, enc))) > 0 {
		return true
	}
	if enc.Recv == nil || len(enc.Recv.List) == 0 {
		// Non-method with no callers: an exported function in a linked
		// package may still be invoked through func values or plugin
		// surfaces — keep it (unknown-biased). Unexported zero-caller
		// functions in linked packages are dead but reflect/go:linkname
		// can still reach them, so they stay too.
		return true
	}
	if enc.Name.Name == "" || !ast.IsExported(enc.Name.Name) {
		return false
	}
	return ix.methodDispatchExists(pkg, enc)
}

// pkgLinked reports whether pkg is reachable in the program's import
// closure — i.e. imported (transitively) from the product roots. Packages
// the module ships but nothing imports (fuzz harnesses, corpus
// generators) are dead code for this build.
func (ix *Index) pkgLinked(pkg *packages.Package) bool {
	return ix.linkedPaths()[pkg.PkgPath]
}

// linkedPaths returns the set of package paths reachable in the
// program's import closure — imported (transitively) from the product
// roots.
func (ix *Index) linkedPaths() map[string]bool {
	if ix.linkedSet == nil || ix.linkedGen != ix.extrasGen {
		ix.linkedSet = map[string]bool{}
		ix.linkedGen = ix.extrasGen
		// Walk the types-level import graph (types.Package.Imports()):
		// package stubs are loaded without NeedImports so Package.Imports
		// is empty, but the types graph is always complete.
		var stack []*types.Package
		push := func(tp *types.Package) {
			if tp != nil && !ix.linkedSet[tp.Path()] {
				ix.linkedSet[tp.Path()] = true
				stack = append(stack, tp)
			}
		}
		for _, p := range ix.pkgs {
			push(p.Types)
		}
		for len(stack) > 0 {
			p := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, imp := range p.Imports() {
				push(imp)
			}
		}
	}
	return ix.linkedSet
}

// reflectDispatchAPIs maps reflect-driven marshaling method names to the
// API packages that dispatch them (json.Unmarshal invokes UnmarshalJSON
// through reflect even though no interface call site names it).
var reflectDispatchAPIs = map[string][]string{
	"UnmarshalJSON":         {"encoding/json"},
	"MarshalJSON":           {"encoding/json"},
	"UnmarshalText":         {"encoding/json", "encoding", "encoding/xml", "flag", "gopkg.in/yaml.v2", "gopkg.in/yaml.v3"},
	"MarshalText":           {"encoding/json", "encoding", "encoding/xml", "flag", "gopkg.in/yaml.v2", "gopkg.in/yaml.v3"},
	"UnmarshalXML":          {"encoding/xml"},
	"MarshalXML":            {"encoding/xml"},
	"UnmarshalBinary":       {"encoding", "encoding/gob"},
	"MarshalBinary":         {"encoding", "encoding/gob"},
	"UnmarshalGob":          {"encoding/gob"},
	"MarshalGob":            {"encoding/gob"},
	"UnmarshalYAML":         {"gopkg.in/yaml.v2", "gopkg.in/yaml.v3"},
	"MarshalYAML":           {"gopkg.in/yaml.v2", "gopkg.in/yaml.v3"},
	"UnmarshalMapstructure": {"github.com/mitchellh/mapstructure", "github.com/go-viper/mapstructure/v2"},
}

// methodDispatchExists reports whether an exported method with zero
// static callers can still be invoked dynamically: reflect Method-by-name
// lookups on its literal name, or a reflect-driven marshaling API whose
// call sites can carry the receiver type.
func (ix *Index) methodDispatchExists(pkg *packages.Package, enc *ast.FuncDecl) bool {
	apis, ok := reflectDispatchAPIs[enc.Name.Name]
	if !ok {
		// Not a known reflect-dispatched method — the invocation surface
		// may still exist (interface wrappers, plugin registries); keep it
		// unknown-biased rather than claim unreachability.
		return true
	}
	if ix.reflectLookupExists(enc.Name.Name) {
		return true
	}
	return ix.marshalAPICarrierExists(pkg, enc, apis)
}

// reflectLookupExists reports whether any linked package performs a
// literal reflect Method/MethodByName lookup for the given method name.
func (ix *Index) reflectLookupExists(name string) bool {
	for _, pkg := range ix.linkedPkgs() {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		found := false
		for _, f := range pkg.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || (sel.Sel.Name != "MethodByName" && sel.Sel.Name != "Method") {
					return true
				}
				if bl, ok := call.Args[0].(*ast.BasicLit); ok && strings.Trim(bl.Value, `"`) == name {
					found = true
					return false
				}
				return true
			})
			if found {
				return true
			}
		}
	}
	return false
}

// marshalAPICarrierExists reports whether any call site into the given
// API packages can carry the enclosing method's receiver type — i.e.
// whether the reflect-dispatched method is actually invocable in this
// build. An argument can carry the receiver when it is an interface type,
// the receiver type itself, or a composite containing it.
func (ix *Index) marshalAPICarrierExists(pkg *packages.Package, enc *ast.FuncDecl, apis []string) bool {
	recv := receiverNamedType(pkg, enc)
	if recv == nil {
		return true // receiver type unresolvable — cannot prove non-carriage
	}
	want := enc.Name.Name
	// Scan linked packages for calls into the API packages; a call is a
	// carrier only when some argument's type may implement the method.
	for _, p := range ix.linkedPkgs() {
		info := p.TypesInfo
		if info == nil {
			continue
		}
		found := false
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn, ok := calleeObject(info, call.Fun).(*types.Func)
				if !ok || fn.Pkg() == nil || !inPkgPrefixes(fn.Pkg().Path(), apis) {
					return true
				}
				for _, a := range call.Args {
					if typeMayCarry(info.TypeOf(a), recv, want) {
						found = true
						return false
					}
				}
				return true
			})
			if found {
				return true
			}
		}
	}
	return false
}

// receiverNamedType resolves the named receiver type of a method decl.
func receiverNamedType(pkg *packages.Package, enc *ast.FuncDecl) *types.Named {
	if enc.Recv == nil || len(enc.Recv.List) == 0 {
		return nil
	}
	t := pkg.TypesInfo.TypeOf(enc.Recv.List[0].Type)
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, _ := t.(*types.Named)
	return named
}

// typeMayCarry reports whether a value of type t could invoke method
// `want` through reflect dispatch: interfaces and type parameters can
// hold anything, the receiver type (or pointer to it) dispatches
// directly, and containers/structs hand their elements upward.
func typeMayCarry(t types.Type, recv *types.Named, want string) bool {
	if t == nil {
		return true
	}
	switch tt := t.(type) {
	case *types.Interface:
		return true
	case *types.Pointer:
		return typeMayCarry(tt.Elem(), recv, want)
	case *types.Named:
		if tt == recv {
			return true
		}
		ms := types.NewMethodSet(t)
		for i := 0; i < ms.Len(); i++ {
			if ms.At(i).Obj().Name() == want {
				return true
			}
		}
		if st, ok := tt.Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				if typeMayCarry(st.Field(i).Type(), recv, want) {
					return true
				}
			}
		}
	case *types.Slice, *types.Array, *types.Map, *types.Chan:
		return typeMayCarry(containerElem(t), recv, want)
	}
	return false
}

func containerElem(t types.Type) types.Type {
	switch tt := t.(type) {
	case *types.Slice:
		return tt.Elem()
	case *types.Array:
		return tt.Elem()
	case *types.Map:
		return tt.Elem()
	case *types.Chan:
		return tt.Elem()
	}
	return nil
}

func inPkgPrefixes(path string, apis []string) bool {
	for _, a := range apis {
		if path == a || strings.HasPrefix(path, a+"/") {
			return true
		}
	}
	return false
}

// linkedPkgs returns the package list inside the program's import
// closure: product roots plus every transitively imported package that
// has been loaded.
func (ix *Index) linkedPkgs() []*packages.Package {
	var out []*packages.Package
	out = append(out, ix.pkgs...)
	seen := map[string]bool{}
	var stack []*types.Package
	push := func(tp *types.Package) {
		if tp != nil && !seen[tp.Path()] {
			seen[tp.Path()] = true
			stack = append(stack, tp)
		}
	}
	for _, p := range ix.pkgs {
		push(p.Types)
	}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, imp := range p.Imports() {
			push(imp)
		}
	}
	// Dep packages loaded on demand are linked whenever the program's
	// import closure contains them — their own syntax matters for scans.
	for _, extras := range ix.extraPkgs {
		for _, extra := range extras {
			if seen[extra.PkgPath] {
				out = append(out, extra)
			}
		}
	}
	return out
}

// paramIndexOf returns the positional index of the parameter named `name`
// in fn's signature, or -1 when fn does not declare it.
func paramIndexOf(fn *ast.FuncDecl, name string) int {
	if fn == nil || fn.Type == nil || fn.Type.Params == nil {
		return -1
	}
	idx := 0
	for _, f := range fn.Type.Params.List {
		for _, n := range f.Names {
			if n.Name == name {
				return idx
			}
			idx++
		}
	}
	return -1
}

// funcSymbolRef builds the SymbolRef callers are found under: methods are
// qualified with the receiver type name.
func funcSymbolRef(pkg *packages.Package, fn *ast.FuncDecl) domain.SymbolRef {
	ref := domain.SymbolRef{Package: pkg.PkgPath, Symbol: fn.Name.Name}
	if fn.Recv != nil && len(fn.Recv.List) > 0 && pkg.TypesInfo != nil {
		if t := pkg.TypesInfo.TypeOf(fn.Recv.List[0].Type); t != nil {
			ref.Symbol = recvTypeName(t) + "." + fn.Name.Name
		}
	}
	return ref
}

// mergeOrigin picks the most attacker-influencing origin of two.
func mergeOrigin(a, b domain.DataOrigin) domain.DataOrigin {
	if a == "" {
		return b
	}
	if rank[b] > rank[a] {
		return b
	}
	return a
}

func mergeOrigins(aO domain.DataOrigin, aW string, bO domain.DataOrigin, bW string) (domain.DataOrigin, string) {
	o := mergeOrigin(aO, bO)
	return o, fmt.Sprintf("{%s | %s}", aW, bW)
}

var rank = map[domain.DataOrigin]int{
	domain.OriginConstant:              0,
	domain.OriginGenerated:             1,
	domain.OriginConfiguration:         2,
	domain.OriginDatabase:              3,
	domain.OriginInternalService:       4,
	domain.OriginUnknown:               5,
	domain.OriginExternalAuthenticated: 6,
	domain.OriginExternalUntrusted:     7,
}

// FindAllValidations runs the per-argument validation scan over every
// argument of the sink call — for conditions whose input position is not
// pinned (ArgIndex < 0).
func (ix *Index) FindAllValidations(ctx context.Context, site domain.CallSite) ([]domain.Validation, []domain.Evidence, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, nil, err
	}
	call, _, _, err := ix.callAt(site)
	if err != nil {
		return nil, nil, err
	}
	var vals []domain.Validation
	var ev []domain.Evidence
	for i := range call.Args {
		v, _, err := ix.findValidations(ctx, site, i)
		if err != nil {
			return vals, ev, err
		}
		vals = append(vals, v...)
	}
	return vals, ev, nil
}

// FindValidations locates guard statements in the enclosing function that
// constrain the argument before the sink call.
func (ix *Index) FindValidations(ctx context.Context, site domain.CallSite, argIndex int) ([]domain.Validation, []domain.Evidence, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	return ix.findValidations(ctx, site, argIndex)
}

func (ix *Index) findValidations(ctx context.Context, site domain.CallSite, argIndex int) ([]domain.Validation, []domain.Evidence, error) {
	var vals []domain.Validation
	var ev []domain.Evidence
	if err := ix.load(ctx); err != nil {
		return nil, nil, err
	}
	call, enc, pkg, err := ix.callAt(site)
	if err != nil {
		return nil, nil, err
	}
	if enc == nil || enc.Body == nil || argIndex < 0 || argIndex >= len(call.Args) {
		return nil, nil, nil
	}
	argIdent := argIdentifier(call.Args[argIndex])
	vals = append(vals, ix.frameGuards(pkg, enc, call, argIdent)...)
	vals = append(vals, ix.fieldWriteGuards(pkg, site, call.Args[argIndex])...)
	for i := range vals {
		vals[i].Arg = argIndex
	}
	return vals, ev, nil
}

// selectorFieldVar resolves a field selection (r.prefetchCount) to its
// field object, nil for plain idents/method selects.
func selectorFieldVar(info *types.Info, e ast.Expr) *types.Var {
	se, ok := e.(*ast.SelectorExpr)
	if !ok {
		return nil
	}
	if sel, ok := info.Selections[se]; ok && sel.Kind() == types.FieldVal {
		if v, ok := sel.Obj().(*types.Var); ok {
			return v
		}
	}
	return nil
}

// fieldWriteGuards collects guards that constrain a field's value at its
// write sites: a sink reading `r.f` is bounded by a clamp inside the
// setter (`switch { case v>m: v=m }`) rather than by anything before the
// read. When every write site stores a constant or is preceded by a guard
// on the assigned identifier, a summary Validation with Covers=<sink> is
// emitted — the value reaching the read is bounded wherever it was set.
func (ix *Index) fieldWriteGuards(pkg *packages.Package, sink domain.CallSite, argExpr ast.Expr) []domain.Validation {
	fv := selectorFieldVar(pkg.TypesInfo, argExpr)
	if fv == nil {
		return nil
	}
	sites := ix.fieldWriteSites(fv)
	if len(sites) == 0 {
		return nil
	}
	var out []domain.Validation
	// &x.f anywhere hands out a writable alias — pointer writes through it
	// are invisible to the syntactic write-site scan, so coverage claims
	// must not be emitted.
	if ix.fieldAddressTaken(fv) {
		out = append(out, domain.Validation{
			CallSite:    sink,
			Property:    fmt.Sprintf("field %s has its address taken (&x.%s); writes through the pointer alias are invisible", fv.Name(), fv.Name()),
			Conditional: true,
		})
		return out
	}
	allBounded := true
	// Aggregate the enforced range across sites: the value stored is the
	// union of every site's installs, so bounds widen (min low / max high)
	// and drop a side any site leaves unbounded.
	u := unionRange{loOK: true, hiOK: true}
	for _, w := range sites {
		if v, ok := exprIntValue(w.pkg.TypesInfo, w.rhs); ok {
			u.add(&v, &v)
			continue // stores a constant — trivially bounded
		}
		name := argIdentifier(w.rhs)
		if name == "" || w.enc == nil || w.enc.Body == nil {
			allBounded = false
			continue
		}
		var g []domain.Validation
		ix.scanGuardStmts(w.pkg, w.enc.Body.List, w.pos, name, false, &g)
		guarded := false
		var siteLo, siteHi *int64
		for _, v := range g {
			if v.Guard && !v.Conditional {
				guarded = true
				siteLo = mergePtrMin(siteLo, v.BoundLow)
				siteHi = mergePtrMax(siteHi, v.BoundHigh)
			}
			v.Property = fmt.Sprintf("field-write %s: %s", fv.Name(), v.Property)
			out = append(out, v)
		}
		if !guarded {
			allBounded = false
			continue
		}
		u.add(siteLo, siteHi)
	}
	if allBounded && len(sites) > 0 {
		lo, hi := u.bounds()
		out = append(out, domain.Validation{
			CallSite:  sink,
			Property:  fmt.Sprintf("every write site of field %s stores a bounded value (setter-side clamp or constant)", fv.Name()),
			Guard:     true,
			Covers:    &sink,
			BoundLow:  lo,
			BoundHigh: hi,
		})
	}
	return out
}

// mergePtrMin/mergePtrMax union two optional bounds — the wider side
// wins; nil means unbounded on that side and dominates.
func mergePtrMin(a, b *int64) *int64 {
	if a == nil || b == nil {
		return nil
	}
	if *b < *a {
		return b
	}
	return a
}

func mergePtrMax(a, b *int64) *int64 {
	if a == nil || b == nil {
		return nil
	}
	if *b > *a {
		return b
	}
	return a
}

// frameGuards scans enc's body for guard statements on ident that precede
// the call expression (same-frame guards).
func (ix *Index) frameGuards(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr, ident string) []domain.Validation {
	var vals []domain.Validation
	if enc == nil || enc.Body == nil {
		return nil
	}
	ix.scanGuardStmts(pkg, enc.Body.List, call.Pos(), ident, false, &vals)
	return vals
}

// scanGuardStmts walks statements that precede callPos, recording guards and
// origin assignments on ident. Statements nested inside if/else/for/switch
// bodies are conditional: the guard fires only when the enclosing condition
// holds, so it is recorded with Conditional=true and cannot unconditionally
// cover a sink. Guards found in the same body that contains the call are
// still conditional on that body's guard condition.
func (ix *Index) scanGuardStmts(pkg *packages.Package, list []ast.Stmt, callPos token.Pos,
	ident string, conditional bool, out *[]domain.Validation) {
	for _, stmt := range list {
		if stmt.Pos() >= callPos {
			break
		}
		if v := stmtValidation(ix, pkg, stmt, ident); v != nil {
			p := ix.fset.Position(stmt.Pos())
			v.File = p.Filename
			v.Line = p.Line
			v.Conditional = conditional
			*out = append(*out, *v)
			continue
		}
		switch s := stmt.(type) {
		case *ast.IfStmt:
			ix.scanGuardStmts(pkg, s.Body.List, callPos, ident, true, out)
			switch e := s.Else.(type) {
			case *ast.BlockStmt:
				ix.scanGuardStmts(pkg, e.List, callPos, ident, true, out)
			case *ast.IfStmt:
				ix.scanGuardStmts(pkg, []ast.Stmt{e}, callPos, ident, true, out)
			}
		case *ast.ForStmt:
			ix.scanGuardStmts(pkg, s.Body.List, callPos, ident, true, out)
		case *ast.RangeStmt:
			ix.scanGuardStmts(pkg, s.Body.List, callPos, ident, true, out)
		case *ast.SwitchStmt:
			if s.Body != nil {
				ix.scanGuardStmts(pkg, s.Body.List, callPos, ident, true, out)
			}
		case *ast.SelectStmt:
			if s.Body != nil {
				ix.scanGuardStmts(pkg, s.Body.List, callPos, ident, true, out)
			}
		case *ast.CaseClause:
			ix.scanGuardStmts(pkg, s.Body, callPos, ident, true, out)
		case *ast.CommClause:
			ix.scanGuardStmts(pkg, s.Body, callPos, ident, true, out)
		case *ast.BlockStmt:
			// A bare block does not add a condition; keep the flag.
			ix.scanGuardStmts(pkg, s.List, callPos, ident, conditional, out)
		}
	}
}

// FindValidationsBound extends FindValidations up the caller chain: the
// sink argument is traced to an enclosing-function parameter, every caller
// of that function is checked for a guard on the mapped argument, and the
// climb repeats through caller parameters up to hops.
//
// A Validation with Covers=<sink site> is emitted only when every caller
// frame of every expanded branch guards the argument — partial caller
// coverage cannot justify a FALSE claim, so those guards are recorded
// without Covers (informational evidence, not sink coverage).
func (ix *Index) FindValidationsBound(ctx context.Context, site domain.CallSite, argIndex, hops int) ([]domain.Validation, []domain.Evidence, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	var ev []domain.Evidence
	if err := ix.load(ctx); err != nil {
		return nil, nil, err
	}
	call, enc, pkg, err := ix.callAt(site)
	if err != nil {
		return nil, nil, err
	}
	if enc == nil || enc.Body == nil || argIndex < 0 || argIndex >= len(call.Args) {
		return nil, nil, nil
	}
	argIdent := argIdentifier(call.Args[argIndex])
	vals := ix.frameGuards(pkg, enc, call, argIdent)
	vals = append(vals, ix.fieldWriteGuards(pkg, site, call.Args[argIndex])...)
	for i := range vals {
		vals[i].Arg = argIndex
	}
	if len(vals) > 0 {
		return vals, ev, nil // sink frame already guards — nothing to climb
	}
	idx := paramIndexOf(enc, argIdent)
	if idx < 0 {
		return vals, ev, nil // argument does not reach a parameter — cannot climb
	}

	type frame struct {
		pkg      *packages.Package
		enc      *ast.FuncDecl
		paramIdx int
		depth    int
	}
	queue := []frame{{pkg: pkg, enc: enc, paramIdx: idx}}
	seen := map[string]bool{fmt.Sprintf("%s.%s:%d", pkg.PkgPath, funcSymbolRef(pkg, enc).Symbol, idx): true}
	allGuarded := true
	for len(queue) > 0 {
		fr := queue[0]
		queue = queue[1:]
		if fr.depth >= hops {
			allGuarded = false
			continue
		}
		refs, err := ix.findCallSites(ctx, funcSymbolRef(fr.pkg, fr.enc))
		if err != nil || len(refs) == 0 {
			allGuarded = false // entrypoint/dynamic callers — unproven path
			continue
		}
		for _, r := range refs {
			if fr.paramIdx >= len(r.call.Args) {
				allGuarded = false
				continue
			}
			ident := argIdentifier(r.call.Args[fr.paramIdx])
			if g := ix.frameGuards(r.pkg, r.enclosing, r.call, ident); len(g) > 0 {
				vals = append(vals, g...)
				continue
			}
			next := paramIndexOf(r.enclosing, ident)
			key := fmt.Sprintf("%s.%s:%d", r.pkg.PkgPath, funcSymbolRef(r.pkg, r.enclosing).Symbol, next)
			if next < 0 || seen[key] {
				allGuarded = false
				continue
			}
			seen[key] = true
			queue = append(queue, frame{pkg: r.pkg, enc: r.enclosing, paramIdx: next, depth: fr.depth + 1})
		}
	}
	if allGuarded && len(vals) > 0 {
		covered := site
		vals = append(vals, domain.Validation{
			CallSite: site,
			Property: "all expanded caller frames guard the argument before it reaches this sink",
			Covers:   &covered,
		})
	}
	for i := range vals {
		vals[i].Arg = argIndex
	}
	return vals, ev, nil
}

func argIdentifier(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return argIdentifier(v.X)
	case *ast.CallExpr:
		if len(v.Args) > 0 {
			return argIdentifier(v.Args[0])
		}
		// `x.Bytes()` / `x.String()` — zero-arg accessor: the guarded value
		// is the receiver.
		if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
			return argIdentifier(sel.X)
		}
	}
	return ""
}

// stmtValidation inspects a statement before the sink for constraints on
// ident: `if <pred on ident> { return/panic }`, a sanitize guard
// `if <cmp on ident> { ident = <clean> }` / exhaustive sanitize-switch,
// or `ident = sanitize(ident)` origin records.
func stmtValidation(ix *Index, pkg *packages.Package, stmt ast.Stmt, ident string) *domain.Validation {
	switch s := stmt.(type) {
	case *ast.IfStmt:
		if ident == "" || !exprMentions(s.Cond, ident) {
			return nil
		}
		if terminates(s.Body) {
			condSrc, _ := ix.nodeSource(s.Cond)
			v := &domain.Validation{Property: condSrc, Guard: true}
			v.BoundLow, v.BoundHigh = condBounds(pkg.TypesInfo, s.Cond, ident)
			return v
		}
		// `if count > max { count = max }` — a clamp: the branch reassigns
		// ident to a value not derived from ident whenever the violation
		// check fires; the false path keeps the already-in-range value.
		if p, lo, hi, ok := sanitizeIf(ix, pkg, s, ident); ok {
			return &domain.Validation{Property: p, Guard: true, BoundLow: lo, BoundHigh: hi}
		}
	case *ast.SwitchStmt:
		// `switch { case count<0: count=0; case count>max: count=max }` —
		// every listed case sanitizes or terminates ident, and inputs
		// matching no case pass through already-in-range. Only marked a
		// guard when every clause conforms.
		if p, lo, hi, ok := sanitizeSwitch(ix, pkg, s, ident); ok {
			return &domain.Validation{Property: p, Guard: true, BoundLow: lo, BoundHigh: hi}
		}
	case *ast.AssignStmt:
		for i, lhs := range s.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != ident || i >= len(s.Rhs) {
				continue
			}
			rhs, _ := ix.nodeSource(s.Rhs[i])
			return &domain.Validation{Property: ident + " <- " + rhs}
		}
	}
	return nil
}

// sanitizeIf reports whether an if-statement bounds ident: the condition
// compares ident, the body reassigns it with a clean RHS or terminates,
// and any else-branch does the same or is empty. low/high report the
// inclusive range the guard enforces on ident when resolvable.
func sanitizeIf(ix *Index, pkg *packages.Package, s *ast.IfStmt, ident string) (string, *int64, *int64, bool) {
	if ident == "" || !exprMentions(s.Cond, ident) || !isComparison(s.Cond) {
		return "", nil, nil, false
	}
	if !branchBounds(pkg.TypesInfo, s.Body, ident) {
		return "", nil, nil, false
	}
	// The enforced range is the union of the surviving pass range
	// (complement of the condition, only when a path keeps ident's value)
	// and the values each clause installs.
	u := unionRange{loOK: true, hiOK: true}
	plo, phi := condBounds(pkg.TypesInfo, s.Cond, ident)
	pass := s.Else == nil
	for _, v := range cleanAssignVals(pkg.TypesInfo, s.Body, ident) {
		if v == nil {
			u.add(nil, nil) // unresolvable install: bound unknown
			continue
		}
		u.add(v, v)
	}
	switch e := s.Else.(type) {
	case nil:
	case *ast.BlockStmt:
		els := cleanAssignVals(pkg.TypesInfo, e, ident)
		if len(els) == 0 {
			pass = true // else does not write ident — value passes through
		}
		if len(e.List) > 0 {
			if !branchBounds(pkg.TypesInfo, e, ident) {
				return "", nil, nil, false
			}
			for _, v := range els {
				if v == nil {
					u.add(nil, nil)
					continue
				}
				u.add(v, v)
			}
		}
	case *ast.IfStmt:
		_, elo, ehi, ok := sanitizeIf(ix, pkg, e, ident)
		if !ok {
			return "", nil, nil, false
		}
		u.add(elo, ehi)
	default:
		return "", nil, nil, false
	}
	if pass {
		u.add(plo, phi)
	}
	condSrc, _ := ix.nodeSource(s.Cond)
	low, high := u.bounds()
	return "sanitize-if " + condSrc, low, high, true
}

// condBounds extracts the inclusive bound a comparison imposes on values
// of ident that survive it (the condition's no-fire side): `v < 0`
// bounds survivors at >= 0. Only single-var comparisons qualify.
func condBounds(info *types.Info, cond ast.Expr, ident string) (*int64, *int64) {
	b, ok := cond.(*ast.BinaryExpr)
	if !ok {
		return nil, nil
	}
	vars := exprVarIdents(info, b)
	if len(vars) != 1 || !vars[ident] {
		return nil, nil
	}
	lo, hi, val := boundsDirection(info, b)
	if lo {
		return val, nil
	}
	if hi {
		return nil, val
	}
	return nil, nil
}

// cleanAssignVals resolves the values a block installs into ident —
// literals and named constants. A nil element marks an unresolvable RHS.
func cleanAssignVals(info *types.Info, b *ast.BlockStmt, ident string) []*int64 {
	if b == nil {
		return nil
	}
	var out []*int64
	for _, st := range b.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != ident || i >= len(as.Rhs) {
				continue
			}
			if exprMentions(as.Rhs[i], ident) {
				continue // self-derived — not a clean install
			}
			if v, ok := exprIntValue(info, as.Rhs[i]); ok {
				out = append(out, &v)
			} else {
				out = append(out, nil)
			}
		}
	}
	return out
}

// unionRange accumulates the tightest inclusive bounds covering every
// added component range — pass-through ranges and installed clean
// values. A component missing a bound on a side makes the union
// unbounded on that side: over-approximating the range is the
// conservative direction for falsification checks.
type unionRange struct {
	lo, hi     *int64
	loOK, hiOK bool
}

func (u *unionRange) add(lo, hi *int64) {
	u.loOK = u.loOK && lo != nil
	u.hiOK = u.hiOK && hi != nil
	if lo != nil && (u.lo == nil || *lo < *u.lo) {
		v := *lo
		u.lo = &v
	}
	if hi != nil && (u.hi == nil || *hi > *u.hi) {
		v := *hi
		u.hi = &v
	}
}

func (u *unionRange) bounds() (*int64, *int64) {
	var lo, hi *int64
	if u.loOK {
		lo = u.lo
	}
	if u.hiOK {
		hi = u.hi
	}
	return lo, hi
}

// sanitizeSwitch reports whether a tagless switch bounds ident. Two
// shapes are accepted:
//
//   - self-sanitize: every case condition compares ident itself and every
//     clause body reassigns it to a bounded value or terminates
//     (`case count>max: count=max`).
//   - range-gated write: the cases compare one other variable cv and
//     bound it on both sides (`case size<0`, `case size>max`), while
//     every clause assigns ident a bounded value — the default clause may
//     additionally assign `ident = T(cv)`/bare cv, since a value reaching
//     it already sits inside the checked range
//     (`default: prefetchSize = FileSize(size)`).
//
// A case condition mentioning no variable, or mixing several, makes the
// switch unanalyzable — not a guard.
func sanitizeSwitch(ix *Index, pkg *packages.Package, s *ast.SwitchStmt, ident string) (string, *int64, *int64, bool) {
	if ident == "" || s.Tag != nil || s.Body == nil || len(s.Body.List) == 0 {
		return "", nil, nil, false
	}
	// First pass: find the single compared variable across case
	// conditions and whether it is bounded on both sides. The pass range
	// (inputs surviving every clause) is the intersection of complements:
	// lo = max of lower thresholds, hi = min of upper thresholds.
	cmpVar := ident
	vars := map[string]bool{}
	var passLo, passHi *int64
	for _, stmt := range s.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			return "", nil, nil, false
		}
		for _, e := range cc.List {
			if !isComparison(e) {
				return "", nil, nil, false
			}
			b := e.(*ast.BinaryExpr)
			vs := exprVarIdents(pkg.TypesInfo, b)
			if len(vs) != 1 {
				return "", nil, nil, false
			}
			for v := range vs {
				vars[v] = true
			}
			lo, hi, val := boundsDirection(pkg.TypesInfo, b)
			if lo && (passLo == nil || *val > *passLo) {
				passLo = val
			}
			if hi && (passHi == nil || *val < *passHi) {
				passHi = val
			}
		}
	}
	if len(vars) > 1 {
		return "", nil, nil, false
	}
	for v := range vars {
		cmpVar = v
	}
	cases := 0
	hasDefault := false
	// The enforced range unions the pass-through range (unmatched inputs
	// keep the bounded-by-complement value, or a range-gated default
	// assigns a conversion of it) and each clause's installed constants.
	u := unionRange{loOK: true, hiOK: true}
	for _, stmt := range s.Body.List {
		cc := stmt.(*ast.CaseClause)
		if cc.List != nil {
			cases++
		} else {
			hasDefault = true
		}
		block := &ast.BlockStmt{List: cc.Body}
		if branchBounds(pkg.TypesInfo, block, ident) {
			for _, v := range cleanAssignVals(pkg.TypesInfo, block, ident) {
				if v == nil {
					u.add(nil, nil)
					continue
				}
				u.add(v, v)
			}
			continue
		}
		// Range-gated write: only the default clause sees values that
		// survived every bound check; assigning it a conversion of the
		// two-side-bounded compared var keeps ident bounded.
		if cc.List == nil && cmpVar != ident && passLo != nil && passHi != nil &&
			branchBoundsGated(pkg.TypesInfo, block, ident, cmpVar) {
			continue
		}
		return "", nil, nil, false
	}
	if cases == 0 {
		return "", nil, nil, false
	}
	// Range-gated mode needs a default: without it an unmatched cv leaves
	// ident's previous value in place, which is not provably bounded. In
	// self-sanitize mode the pass-through keeps the already-in-range ident.
	if cmpVar != ident && !hasDefault {
		return "", nil, nil, false
	}
	if !hasDefault || cmpVar == ident {
		// No default → unmatched values pass through inside the checked
		// range; a self-sanitize default assigns a bounded install too.
		u.add(passLo, passHi)
	} else if cmpVar != ident {
		// The gated default installed ident = f(cv) — cv sits inside the
		// checked range, so ident inherits it.
		u.add(passLo, passHi)
	}
	if cmpVar != ident {
		lo, hi := u.bounds()
		return fmt.Sprintf("sanitize-switch on %s range-gated by %s (%d case(s))", ident, cmpVar, cases), lo, hi, true
	}
	lo, hi := u.bounds()
	return fmt.Sprintf("sanitize-switch on %s (%d case(s))", ident, cases), lo, hi, true
}

// exprVarIdents collects the distinct variable identifiers (types.Var)
// inside e — the candidates for the variable a comparison bounds.
// Constants, type names and function names are not variables.
func exprVarIdents(info *types.Info, e ast.Expr) map[string]bool {
	out := map[string]bool{}
	ast.Inspect(e, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		if _, ok := info.ObjectOf(id).(*types.Var); ok {
			out[id.Name] = true
		}
		return true
	})
	return out
}

// boundsDirection classifies a comparison `a OP b` as a lower- and/or
// upper-bound check on the surviving range: `v < x` diverts values below
// x (lower bound on what passes), `v > x` diverts above (upper bound).
// The side holding the variable decides the direction; when both sides
// are variables the bound is ambiguous and neither flag is set. val is
// the inclusive bound the passing values satisfy, resolved when the
// non-variable side is a literal or named constant: `v <= K` bounds the
// pass range at K+1, `v >= K` at K-1.
func boundsDirection(info *types.Info, b *ast.BinaryExpr) (lower, upper bool, bound *int64) {
	lv := len(exprVarIdents(info, b.X)) > 0
	rv := len(exprVarIdents(info, b.Y)) > 0
	if lv == rv {
		return false, false, nil
	}
	op := b.Op
	side := b.Y
	if rv {
		// Mirror the comparison so the variable is on the left.
		op = mirrorOp(op)
		side = b.X
	}
	if k, ok := exprIntValue(info, side); ok {
		bound = &k
	}
	switch op {
	case token.LSS: // v < K: passing values are >= K
		return true, false, bound
	case token.LEQ: // v <= K: passing values are > K
		if bound != nil {
			*bound++
		}
		return true, false, bound
	case token.GTR: // v > K: passing values are <= K
		return false, true, bound
	case token.GEQ: // v >= K: passing values are < K
		if bound != nil {
			*bound--
		}
		return false, true, bound
	}
	return false, false, nil
}

// exprIntValue resolves e to an int64 when it is an integer literal, a
// named constant, or a single-argument type conversion wrapping one.
func exprIntValue(info *types.Info, e ast.Expr) (int64, bool) {
	if call, ok := e.(*ast.CallExpr); ok && len(call.Args) == 1 {
		if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
			return exprIntValue(info, call.Args[0])
		}
		return 0, false
	}
	if bl, ok := e.(*ast.BasicLit); ok && bl.Kind == token.INT {
		if v, err := strconv.ParseInt(strings.TrimSpace(bl.Value), 0, 64); err == nil {
			return v, true
		}
		return 0, false
	}
	if tv, ok := info.Types[e]; ok && tv.Value != nil &&
		tv.Value.Kind() == constant.Int {
		if v, ok := constant.Int64Val(tv.Value); ok {
			return v, true
		}
	}
	return 0, false
}

func mirrorOp(op token.Token) token.Token {
	switch op {
	case token.LSS:
		return token.GTR
	case token.LEQ:
		return token.GEQ
	case token.GTR:
		return token.LSS
	case token.GEQ:
		return token.LEQ
	}
	return op
}

// branchBoundsGated is branchBounds extended: an assignment to ident is
// also bounded when its RHS is the range-gated variable cv — bare or
// under a conversion/accessor — because the caller has already proven cv
// is bounded on both sides.
func branchBoundsGated(info *types.Info, b *ast.BlockStmt, ident, cv string) bool {
	if b == nil {
		return false
	}
	if terminates(b) {
		return true
	}
	assigns := false
	for _, st := range b.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != ident || i >= len(as.Rhs) {
				continue
			}
			if exprMentions(as.Rhs[i], ident) {
				return false
			}
			if !isBoundedRHS(info, as.Rhs[i]) && !onlyVarsOf(info, as.Rhs[i], cv) {
				return false
			}
			assigns = true
		}
	}
	return assigns
}

// onlyVarsOf reports whether every variable identifier in e is cv — the
// RHS derives only from the range-bounded variable (plus constants and
// conversions).
func onlyVarsOf(info *types.Info, e ast.Expr, cv string) bool {
	vars := exprVarIdents(info, e)
	if len(vars) == 0 {
		return false
	}
	for v := range vars {
		if v != cv {
			return false
		}
	}
	return true
}

// isComparison reports whether e is a binary comparison — the bound-check
// shape a sanitize guard must have (`count > max`, not `ready()`).
func isComparison(e ast.Expr) bool {
	b, ok := e.(*ast.BinaryExpr)
	if !ok {
		return false
	}
	switch b.Op {
	case token.LSS, token.GTR, token.LEQ, token.GEQ, token.EQL, token.NEQ:
		return true
	}
	return false
}

// branchBounds reports whether a block bounds ident: it terminates, or it
// reassigns ident to a provably bounded value — a literal or a named
// constant. `x = compute()` reassigns ident but bounds nothing.
func branchBounds(info *types.Info, b *ast.BlockStmt, ident string) bool {
	if b == nil {
		return false
	}
	if terminates(b) {
		return true
	}
	assigns := false
	for _, st := range b.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok {
			continue
		}
		for i, lhs := range as.Lhs {
			id, ok := lhs.(*ast.Ident)
			if !ok || id.Name != ident || i >= len(as.Rhs) {
				continue
			}
			if exprMentions(as.Rhs[i], ident) || !isBoundedRHS(info, as.Rhs[i]) {
				return false // reassigned from itself or an unbounded value
			}
			assigns = true
		}
	}
	return assigns
}

// isBoundedRHS reports whether e is provably bounded: a literal or a
// named constant (including qualified ones like pkg.MaxInt).
func isBoundedRHS(info *types.Info, e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		_, ok := info.ObjectOf(v).(*types.Const)
		return ok
	case *ast.SelectorExpr:
		_, ok := info.ObjectOf(v.Sel).(*types.Const)
		return ok
	case *ast.UnaryExpr:
		return isBoundedRHS(info, v.X) // -1, ^0, etc.
	}
	return false
}

func exprMentions(e ast.Expr, ident string) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == ident {
			found = true
		}
		return !found
	})
	return found
}

// terminates reports whether the block exits control flow (return or panic).
func terminates(b *ast.BlockStmt) bool {
	for _, s := range b.List {
		switch s := s.(type) {
		case *ast.ReturnStmt:
			return true
		case *ast.BranchStmt:
			if s.Tok.String() == "goto" {
				continue
			}
			return true
		case *ast.ExprStmt:
			if call, ok := s.X.(*ast.CallExpr); ok {
				if id, ok2 := call.Fun.(*ast.Ident); ok2 && id.Name == "panic" {
					return true
				}
			}
		}
	}
	return false
}

// dedupSites collapses repeated (file,line,callee) entries — the same call
// may be traversed more than once through nested classification paths.
func dedupSites(sites []domain.CallSite) []domain.CallSite {
	if len(sites) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := sites[:0]
	for _, s := range sites {
		k := fmt.Sprintf("%s:%d:%s", s.File, s.Line, s.Callee)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, s)
	}
	return out
}
