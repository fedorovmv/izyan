package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"reflect"
	"strings"

	"golang.org/x/tools/go/packages"

	"example.com/vuln-analyzer/internal/domain"
)

// maxTraceHops bounds how far argument provenance follows identifiers into
// callers. Deeper chains resolve to UNKNOWN (a limitation), not a guess.
const maxTraceHops = 2

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
	// Collect the transformation chain: every call the traced value passes
	// through, recorded by classifyCall while txBuf is set. Held under the
	// same mutex as the rest of the trace — nil outside TraceArgument.
	var tx []domain.CallSite
	ix.txBuf = &tx
	ix.traceSeen = map[types.Object]bool{}
	origin, why := ix.classify(pkg, enc, call.Args[argIndex], 0)
	ix.txBuf = nil
	ix.traceSeen = nil
	flow.Origin = origin
	flow.Summary = why
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

// callAt finds the CallExpr at the File:Line position of site.
func (ix *Index) callAt(site domain.CallSite) (*ast.CallExpr, *ast.FuncDecl, *packages.Package, error) {
	for _, pkg := range ix.pkgs {
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
				return found, enc, pkg, nil
			}
		}
	}
	return nil, nil, nil, fmt.Errorf("call site %s:%d not found", site.File, site.Line)
}

// classify resolves the origin of an expression within a function.
// depth limits parameter-hopping into callers.
func (ix *Index) classify(pkg *packages.Package, enc *ast.FuncDecl, expr ast.Expr, depth int) (domain.DataOrigin, string) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		return domain.OriginConstant, "literal constant"
	case *ast.CompositeLit:
		return domain.OriginConstant, "composite literal"
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
		return ix.classify(pkg, enc, e.X, depth)
	case *ast.IndexExpr, *ast.IndexListExpr, *ast.SliceExpr:
		return ix.classify(pkg, enc, childExpr(e), depth)
	case *ast.ParenExpr:
		return ix.classify(pkg, enc, e.X, depth)
	case *ast.TypeAssertExpr:
		return ix.classify(pkg, enc, e.X, depth)
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
	// function parameter: hop into callers of the enclosing function
	if v, ok := obj.(*types.Var); ok && isParam(enc, v) {
		return ix.traceParam(pkg, enc, v, depth)
	}
	// package-level var/const: classify its initializer
	if decl := findVarInit(pkg, v(obj)); decl != nil {
		o, why := ix.classify(pkg, enc, decl, depth+1)
		return o, fmt.Sprintf("package-level %s <- %s", obj.Name(), why)
	}
	// local var: merge every assignment inside the function — branch and
	// case writes all reach the read, so origins join (worst wins). A
	// var already being resolved on this trace is a cycle (x = f(x)).
	if rhsList := localAssigns(enc, obj); len(rhsList) > 0 {
		if ix.traceSeen != nil && ix.traceSeen[obj] {
			return domain.OriginUnknown, fmt.Sprintf("local %s: recursive assignment cycle", id.Name)
		}
		if ix.traceSeen != nil {
			ix.traceSeen[obj] = true
			defer delete(ix.traceSeen, obj)
		}
		var merged domain.DataOrigin
		var whys []string
		for _, rhs := range rhsList {
			o, w := ix.classify(pkg, enc, rhs, depth)
			whys = append(whys, w)
			merged = mergeOrigin(merged, o)
		}
		if merged == "" {
			return domain.OriginUnknown, fmt.Sprintf("local %s: no resolvable assignment", id.Name)
		}
		return merged, fmt.Sprintf("local %s <- {%s}", id.Name, strings.Join(whys, " | "))
	}
	// populated by a call taking &v — rows.Scan(&v), json.Unmarshal(data,&v):
	// the variable is written in place, not assigned.
	if o, why, ok := ix.populateOrigin(pkg, enc, obj, depth); ok {
		return o, fmt.Sprintf("local %s <- %s", id.Name, why)
	}
	return domain.OriginUnknown, fmt.Sprintf("identifier %s without resolvable initializer", id.Name)
}

// populateOrigin detects out-parameter writes: calls of the form
// `f(..., &v)` inside the enclosing function where `v` is our variable.
// DB-ish receivers (`rows.Scan(&v)`, `row.Scan(&v)`) → DATABASE;
// unmarshal/decode families propagate the origin of the data argument;
// grpc/stub out-params → INTERNAL_SERVICE.
func (ix *Index) populateOrigin(pkg *packages.Package, enc *ast.FuncDecl, obj types.Object, depth int) (domain.DataOrigin, string, bool) {
	if enc == nil || enc.Body == nil || depth >= ix.hops() {
		return "", "", false
	}
	var found *ast.CallExpr
	ast.Inspect(enc.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || found != nil {
			return !ok
		}
		for _, a := range call.Args {
			u, ok := a.(*ast.UnaryExpr)
			if !ok || u.Op != token.AND {
				continue
			}
			id, ok := u.X.(*ast.Ident)
			if !ok {
				continue
			}
			if pkg.TypesInfo.ObjectOf(id) == obj {
				found = call
				return false
			}
		}
		return true
	})
	if found == nil {
		return "", "", false
	}
	fn, _ := calleeObject(pkg.TypesInfo, found.Fun).(*types.Func)
	if fn == nil {
		return "", "", false
	}
	if isDBFunc(fn) {
		return domain.OriginDatabase, fmt.Sprintf("%s populates &%s", fn.Name(), obj.Name()), true
	}
	if isServiceCall(fn) {
		return domain.OriginInternalService, fmt.Sprintf("%s populates &%s", fn.Name(), obj.Name()), true
	}
	// unmarshal/decode: origin of the *source* propagates — for methods
	// the source is the receiver (`dec.Decode(&x)`), for package funcs the
	// data argument (`json.Unmarshal(data, &x)`).
	switch fn.Name() {
	case "Unmarshal", "Decode", "DecodeElement", "UnmarshalExact", "DecodeValues":
		var src ast.Expr
		if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
			if sel, ok := found.Fun.(*ast.SelectorExpr); ok {
				src = sel.X
			}
		} else if len(found.Args) > 0 {
			src = found.Args[0]
		}
		if src != nil {
			o, why := ix.classify(pkg, enc, src, depth+1)
			return o, fmt.Sprintf("%s into &%s: %s", fn.Name(), obj.Name(), why), true
		}
	}
	return "", "", false
}

// isDBFunc reports whether fn is a database/kv-store API — method on a
// driver type (sql.Rows, gorm.DB, mongo.Collection, redis.Client...) or a
// package-level helper in a known data-store package.
func isDBFunc(fn *types.Func) bool {
	pkgPath := ""
	if fn.Pkg() != nil {
		pkgPath = fn.Pkg().Path()
	}
	switch {
	case pkgPath == "database/sql",
		strings.Contains(pkgPath, "sqlx"),
		strings.Contains(pkgPath, "gorm"),
		strings.Contains(pkgPath, "pgx"),
		strings.Contains(pkgPath, "mongo"),
		strings.Contains(pkgPath, "redis"),
		strings.Contains(pkgPath, "etcd"),
		strings.Contains(pkgPath, "gocql"),
		strings.Contains(pkgPath, "elasticsearch"):
		return true
	}
	// receiver type in a data-store package (method values too)
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		if n := recvNamed(sig.Recv().Type()); n != nil && n.Obj() != nil && n.Obj().Pkg() != nil {
			p := n.Obj().Pkg().Path()
			switch {
			case p == "database/sql",
				strings.Contains(p, "sqlx"), strings.Contains(p, "gorm"),
				strings.Contains(p, "pgx"), strings.Contains(p, "mongo"),
				strings.Contains(p, "redis"), strings.Contains(p, "etcd"),
				strings.Contains(p, "gocql"), strings.Contains(p, "elasticsearch"):
				return true
			}
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
// imports google.golang.org/grpc — generated *Client stubs.
func isServiceCall(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return false
	}
	n := recvNamed(sig.Recv().Type())
	if n == nil || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	for _, imp := range n.Obj().Pkg().Imports() {
		if strings.Contains(imp.Path(), "google.golang.org/grpc") {
			return true
		}
	}
	return false
}

func isParam(enc *ast.FuncDecl, v *types.Var) bool {
	if enc == nil || enc.Type.Params == nil {
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
	// transparent selector: classify base — keep the enclosing func so the
	// base can resolve to a local variable (resp.Body -> resp assignment).
	return ix.classify(pkg, enc, e.X, depth)
}

// configTagKeys are struct tags whose fields are populated by
// configuration decoding, not request payloads.
var configTagKeys = []string{"mapstructure", "env", "envconfig", "toml", "ini"}

// fieldConfigTagged locates the field's declaration and reports whether
// its struct tag marks a configuration-decoded value.
func (ix *Index) fieldConfigTagged(field *types.Var) bool {
	for _, pkg := range ix.pkgs {
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
					if info.ObjectOf(name) == types.Object(field) {
						found = true
						if fd.Tag != nil {
							tag := strings.Trim(fd.Tag.Value, "`")
							for _, k := range configTagKeys {
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
	pkg *packages.Package
	enc *ast.FuncDecl // nil for package-level writes
	rhs ast.Expr
	pos token.Pos
}

// fieldWriteSites scans product packages for writes to field:
// `x.field = rhs` assignments (any receiver of the same struct type —
// matched by field object identity) and `T{field: rhs}` literals.
func (ix *Index) fieldWriteSites(field *types.Var) []fieldWrite {
	var sites []fieldWrite
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
				switch n := n.(type) {
				case *ast.AssignStmt:
					for i, lhs := range n.Lhs {
						if !writesField(info, lhs, field) {
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
							sites = append(sites, fieldWrite{pkg, enc, rhs, n.Pos()})
						}
					}
				case *ast.KeyValueExpr:
					if id, ok := n.Key.(*ast.Ident); ok && info.ObjectOf(id) == types.Object(field) {
						sites = append(sites, fieldWrite{pkg, enc, n.Value, n.Pos()})
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
	sites := ix.fieldWriteSites(field)
	if len(sites) == 0 {
		return "", "", false
	}
	var merged domain.DataOrigin
	var whys []string
	for _, s := range sites {
		o, w := ix.classify(s.pkg, s.enc, s.rhs, depth+1)
		whys = append(whys, w)
		merged = mergeOrigin(merged, o)
	}
	return merged, fmt.Sprintf("%d write site(s): %s", len(sites), strings.Join(whys, "; ")), true
}

// fieldAddressTaken reports whether any product code takes the field's
// address (&x.f) — such a pointer alias allows writes invisible to
// fieldWriteSites.
func (ix *Index) fieldAddressTaken(field *types.Var) bool {
	found := false
	for _, pkg := range ix.pkgs {
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
					info.ObjectOf(se.Sel) == types.Object(field) {
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
func writesField(info *types.Info, lhs ast.Expr, field *types.Var) bool {
	found := false
	ast.Inspect(lhs, func(n ast.Node) bool {
		if se, ok := n.(*ast.SelectorExpr); ok && info.ObjectOf(se.Sel) == types.Object(field) {
			found = true
			return false
		}
		return !found
	})
	return found
}

func isHTTPRequest(t types.Type) bool {
	s := t.String()
	return strings.HasSuffix(s, "net/http.Request") || strings.HasSuffix(s, "*net/http.Request")
}

// classifyCall handles calls: known source functions, transformations, or
// opaque functions.
func (ix *Index) classifyCall(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr, depth int) (domain.DataOrigin, string) {
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
		*ix.txBuf = append(*ix.txBuf, site)
	}
	if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil {
		key := fn.Pkg().Path() + "." + fn.Name()
		// DB/RPC source calls: result value is store- or service-provided.
		if isDBFunc(fn) {
			return domain.OriginDatabase, fmt.Sprintf("result of %s", key)
		}
		if isServiceCall(fn) {
			return domain.OriginInternalService, fmt.Sprintf("gRPC stub %s", key)
		}
		// Outbound HTTP calls: an internal/configured endpoint is a service
		// boundary, a literal/explicit URL is plain external data.
		if o, why, ok := ix.httpClientOrigin(pkg, enc, fn, call, depth); ok {
			return o, why
		}
		if o, ok := knownSourceFuncs[key]; ok {
			return o, key
		}
		// Carrier constructors/accessors: the result derives from one
		// input — io.ReadAll(r), NewDecoder(r), NewRequest(m,url,b), or
		// accessor methods like scanner.Text()/b.String().
		if idx, ok := passthroughFuncs[key]; ok && idx < len(call.Args) {
			o, why := ix.classify(pkg, enc, call.Args[idx], depth+1)
			return o, fmt.Sprintf("%s(%s)", key, why)
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && passthroughMethods[fn.Name()] {
			o, why := ix.classify(pkg, enc, sel.X, depth)
			return o, fmt.Sprintf("%s() on %s", fn.Name(), why)
		}
		if sig, ok2 := fn.Type().(*types.Signature); ok2 && sig.Recv() != nil && isHTTPRequest(sig.Recv().Type()) {
			return domain.OriginExternalUntrusted, "method on *http.Request"
		}
		// Not a named source: trace into the callee body — if its result is
		// derived purely from parameters/constants, the caller's argument
		// origins propagate. Unresolvable bodies stay UNKNOWN.
		if o, why, ok := ix.traceCallee(fn, call, ix.topEval(pkg, enc), depth); ok {
			return o, why
		}
		return domain.OriginUnknown, fmt.Sprintf("opaque call %s", key)
	}
	// builtins / transformations propagate the origin of their input
	if len(call.Args) > 0 {
		return ix.classify(pkg, enc, call.Args[0], depth)
	}
	return domain.OriginUnknown, "unresolvable call"
}

// httpClientOrigin refines outbound HTTP calls: `http.Get(url)`,
// `client.Do(req)`. When the endpoint argument resolves to configuration
// the response is an INTERNAL_SERVICE value (service chosen by
// deployment); a literal or externally-derived URL stays
// EXTERNAL_UNTRUSTED. Returns ok=false for non-HTTP-client calls.
func (ix *Index) httpClientOrigin(pkg *packages.Package, enc *ast.FuncDecl, fn *types.Func, call *ast.CallExpr, depth int) (domain.DataOrigin, string, bool) {
	pkgPath := fn.Pkg().Path()
	isClientMethod := false
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		if n := recvNamed(sig.Recv().Type()); n != nil && n.Obj() != nil &&
			n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == "net/http" {
			isClientMethod = true
		}
	}
	isPkgFunc := pkgPath == "net/http" &&
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
		if o, _ := ix.classify(pkg, enc, endpoint, depth+1); o == domain.OriginConfiguration || o == domain.OriginDatabase {
			return domain.OriginInternalService,
				fmt.Sprintf("http %s to configured endpoint", fn.Name()), true
		}
	}
	if hasAuthMarkers(enc) {
		return domain.OriginExternalAuthenticated,
			fmt.Sprintf("http %s via authenticated client", fn.Name()), true
	}
	return domain.OriginExternalUntrusted, fmt.Sprintf("http %s response body", fn.Name()), true
}

// authCallNames are callee names that attach credentials to a request or
// client — evidence that a peer is authenticated rather than a random
// internet source.
var authCallNames = map[string]bool{
	"SetBasicAuth": true, "BasicAuth": true, "SetAuth": true,
	"WithAuth": true, "WithCredentials": true, "WithPerRPCCredentials": true,
	"NewOauthAccess": true, "NewStaticTokenSource": true,
	"ReuseTokenSource": true, "SetToken": true,
}

// hasAuthMarkers reports whether the enclosing function attaches
// credentials somewhere in its body: an "Authorization" header literal or
// a call to a credential-attaching helper. Heuristic — it notes that a
// peer is *probably* authenticated, never that input is safe.
func hasAuthMarkers(enc *ast.FuncDecl) bool {
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
			if authCallNames[callName(x.Fun)] {
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

// traceCallee attempts to prove that fn's result derives only from its
// parameters and constants. Returns ok=false when the body is unavailable,
// contaminated by external sources, or too complex to resolve — the caller
// then yields UNKNOWN rather than guessing.
func (ix *Index) traceCallee(fn *types.Func, call *ast.CallExpr, evalArg exprEval, depth int) (domain.DataOrigin, string, bool) {
	if depth >= ix.hops() {
		return "", "", false
	}
	decl, dp := ix.funcDecl(fn)
	if decl == nil || decl.Body == nil || dp == nil || dp.TypesInfo == nil {
		return "", "", false
	}
	if bodyContaminated(dp, decl) {
		return "", "", false
	}
	// map callee parameter name -> index into the call's argument list
	paramIdx := map[string]int{}
	i := 0
	if decl.Type.Params != nil {
		for _, f := range decl.Type.Params.List {
			for _, n := range f.Names {
				paramIdx[n.Name] = i
				i++
			}
		}
	}
	argAt := func(name string) (ast.Expr, bool) {
		j, ok := paramIdx[name]
		if !ok || j >= len(call.Args) {
			return nil, false
		}
		return call.Args[j], true
	}
	var out domain.DataOrigin
	nret := 0
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		rs, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		for _, re := range rs.Results {
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
func (ix *Index) evalCalleeExpr(dp *packages.Package, decl *ast.FuncDecl, e ast.Expr,
	argAt func(string) (ast.Expr, bool), evalArg exprEval, depth int) (domain.DataOrigin, string) {

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
		if arg, ok := argAt(v.Name); ok {
			o, w := evalArg(arg, depth+1)
			return o, "param " + v.Name + " <- " + w
		}
		if rhsList := localAssigns(decl, dp.TypesInfo.ObjectOf(v)); len(rhsList) > 0 {
			var merged domain.DataOrigin
			for _, rhs := range rhsList {
				o, _ := ix.evalCalleeExpr(dp, decl, rhs, argAt, evalArg, depth)
				merged = mergeOrigin(merged, o)
			}
			if merged != "" {
				return merged, "local " + v.Name + " <- merged assignments"
			}
		}
		return domain.OriginUnknown, "unresolvable ident " + v.Name
	case *ast.ParenExpr:
		return ix.evalCalleeExpr(dp, decl, v.X, argAt, evalArg, depth)
	case *ast.UnaryExpr:
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
		if fn2, ok := obj.(*types.Func); ok && fn2.Pkg() != nil {
			key := fn2.Pkg().Path() + "." + fn2.Name()
			if o, ok := knownSourceFuncs[key]; ok {
				return o, key
			}
			inner := func(a ast.Expr, d int) (domain.DataOrigin, string) {
				return ix.evalCalleeExpr(dp, decl, a, argAt, evalArg, d)
			}
			if o, w, ok2 := ix.traceCallee(fn2, v, inner, depth+1); ok2 {
				return o, w
			}
		}
		return domain.OriginUnknown, "nested opaque call"
	}
	return domain.OriginUnknown, fmt.Sprintf("unsupported callee expr %T", e)
}

// bodyContaminated reports whether the callee body reads any external data
// source itself. If it does, we cannot prove the output is input-derived,
// so the result must stay UNKNOWN.
func bodyContaminated(dp *packages.Package, decl *ast.FuncDecl) bool {
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
				if o, ok := knownSourceFuncs[fn.Pkg().Path()+"."+fn.Name()]; ok &&
					o != domain.OriginConstant {
					bad = true
				}
			}
		}
		return !bad
	})
	return bad
}

// funcDecl finds the FuncDecl and package for a function object — product
// package first, then a dependency loaded on demand.
func (ix *Index) funcDecl(fn *types.Func) (*ast.FuncDecl, *packages.Package) {
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
	extra, err := ix.loadExtra(context.Background(), fn.Pkg().Path())
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
		origin, why := ix.classify(pkg, enc, call.Args[i], 0)
		ix.txBuf = nil
		ix.traceSeen = nil
		flows = append(flows, domain.DataFlow{
			Arg:             i,
			Sink:            site,
			Source:          site,
			Origin:          origin,
			Transformations: dedupSites(tx),
			Summary:         fmt.Sprintf("arg%d: %s", i, why),
		})
	}
	return flows, ev, nil
}

// InputParamIndex heuristically selects the parameter index most likely to
// carry attacker-controlled data, from the callee's signature: request-like
// and reader types win over plain data types. Returns -1 when nothing
// looks like input — callers must treat that as UNKNOWN, never guess.
func (ix *Index) InputParamIndex(ref domain.SymbolRef) (int, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cs, err := ix.findSymbol(context.Background(), ref)
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
	extra, err := ix.loadExtra(context.Background(), ref.Package)
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

// knownSourceFuncs maps pkgpath.Func to a data origin. Extend as needed —
// this is provenance, not pattern matching for verdicts.
var knownSourceFuncs = map[string]domain.DataOrigin{
	"os.Getenv":               domain.OriginConfiguration,
	"os.ReadFile":             domain.OriginConfiguration,
	"io/ioutil.ReadFile":      domain.OriginConfiguration,
	"flag.String":             domain.OriginConfiguration,
	"flag.Int":                domain.OriginConfiguration,
	"flag.Bool":               domain.OriginConfiguration,
	"flag.Parse":              domain.OriginConfiguration,
	"fmt.Sscanf":              domain.OriginUnknown,
	"os.Open":                 domain.OriginConfiguration,
	"net/http.Get":            domain.OriginExternalUntrusted,
	"net/http.Post":           domain.OriginExternalUntrusted,
	"net/http.ReadRequest":    domain.OriginExternalUntrusted,
	"encoding/json.Unmarshal": domain.OriginUnknown,
}

// passthroughFuncs maps pkgpath.Func to the argument index whose origin
// the call result carries — readers, decoders, request builders.
var passthroughFuncs = map[string]int{
	"io.ReadAll":                     0,
	"io/ioutil.ReadAll":              0,
	"bufio.NewScanner":               0,
	"bytes.NewReader":                0,
	"bytes.NewBuffer":                0,
	"bytes.NewBufferString":          0,
	"strings.NewReader":              0,
	"encoding/json.NewDecoder":       0,
	"encoding/xml.NewDecoder":        0,
	"net/http.NewRequest":            1, // (method, url, body)
	"net/http.NewRequestWithContext": 2, // (ctx, method, url, body)
	"net/url.Parse":                  0,
	"net/url.ParseQuery":             0,
}

// passthroughMethods: accessor methods whose result carries the receiver's
// data origin — scanner.Text(), buffer.Bytes(), builder.String().
var passthroughMethods = map[string]bool{
	"Text": true, "Bytes": true, "String": true,
}

// traceParam resolves an argument bound to an enclosing function parameter by
// looking at the callers of that function (one hop).
func (ix *Index) traceParam(pkg *packages.Package, enc *ast.FuncDecl, v *types.Var, depth int) (domain.DataOrigin, string) {
	if depth >= ix.hops() || enc == nil || enc.Name == nil {
		return domain.OriginUnknown, fmt.Sprintf("parameter %s of %s: caller tracing depth exceeded (depth=%d)", v.Name(), enc.Name, depth)
	}
	// find which parameter index this is
	paramIdx := paramIndexOf(enc, v.Name())
	if paramIdx < 0 {
		return domain.OriginUnknown, "parameter index not found"
	}
	// callers of enclosing function
	var encRef domain.SymbolRef
	if pkg.Types != nil {
		encRef = funcSymbolRef(pkg, enc)
	}
	refs, err := ix.findCallSites(context.Background(), encRef)
	if err != nil || len(refs) == 0 {
		return domain.OriginUnknown, fmt.Sprintf("no static callers of %s found", enc.Name.Name)
	}
	var merged domain.DataOrigin
	var whys []string
	for _, r := range refs {
		if paramIdx >= len(r.call.Args) {
			continue
		}
		o, w := ix.classify(r.pkg, r.enclosing, r.call.Args[paramIdx], depth+1)
		whys = append(whys, fmt.Sprintf("%s:%d %s", r.Site.File, r.Site.Line, w))
		merged = mergeOrigin(merged, o)
	}
	if merged == "" {
		return domain.OriginUnknown, "no caller arguments resolvable"
	}
	return merged, fmt.Sprintf("param %s via %d caller(s): %s", v.Name(), len(refs), strings.Join(whys, "; "))
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
	for _, w := range sites {
		if _, ok := w.rhs.(*ast.BasicLit); ok {
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
		for _, v := range g {
			if v.Guard && !v.Conditional {
				guarded = true
			}
			v.Property = fmt.Sprintf("field-write %s: %s", fv.Name(), v.Property)
			out = append(out, v)
		}
		if !guarded {
			allBounded = false
		}
	}
	if allBounded && len(sites) > 0 {
		out = append(out, domain.Validation{
			CallSite: sink,
			Property: fmt.Sprintf("every write site of field %s stores a bounded value (setter-side clamp or constant)", fv.Name()),
			Guard:    true,
			Covers:   &sink,
		})
	}
	return out
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
			return &domain.Validation{Property: condSrc, Guard: true}
		}
		// `if count > max { count = max }` — a clamp: the branch reassigns
		// ident to a value not derived from ident whenever the violation
		// check fires; the false path keeps the already-in-range value.
		if p, ok := sanitizeIf(ix, pkg, s, ident); ok {
			return &domain.Validation{Property: p, Guard: true}
		}
	case *ast.SwitchStmt:
		// `switch { case count<0: count=0; case count>max: count=max }` —
		// every listed case sanitizes or terminates ident, and inputs
		// matching no case pass through already-in-range. Only marked a
		// guard when every clause conforms.
		if p, ok := sanitizeSwitch(ix, pkg, s, ident); ok {
			return &domain.Validation{Property: p, Guard: true}
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
// and any else-branch does the same or is empty.
func sanitizeIf(ix *Index, pkg *packages.Package, s *ast.IfStmt, ident string) (string, bool) {
	if ident == "" || !exprMentions(s.Cond, ident) || !isComparison(s.Cond) {
		return "", false
	}
	if !branchBounds(pkg.TypesInfo, s.Body, ident) {
		return "", false
	}
	switch e := s.Else.(type) {
	case nil:
	case *ast.BlockStmt:
		if len(e.List) > 0 && !branchBounds(pkg.TypesInfo, e, ident) {
			return "", false
		}
	case *ast.IfStmt:
		if _, ok := sanitizeIf(ix, pkg, e, ident); !ok {
			return "", false
		}
	default:
		return "", false
	}
	condSrc, _ := ix.nodeSource(s.Cond)
	return "sanitize-if " + condSrc, true
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
func sanitizeSwitch(ix *Index, pkg *packages.Package, s *ast.SwitchStmt, ident string) (string, bool) {
	if ident == "" || s.Tag != nil || s.Body == nil || len(s.Body.List) == 0 {
		return "", false
	}
	// First pass: find the single compared variable across case
	// conditions and whether it is bounded on both sides.
	cmpVar := ident
	vars := map[string]bool{}
	lower, upper := false, false
	for _, stmt := range s.Body.List {
		cc, ok := stmt.(*ast.CaseClause)
		if !ok {
			return "", false
		}
		for _, e := range cc.List {
			if !isComparison(e) {
				return "", false
			}
			b := e.(*ast.BinaryExpr)
			vs := exprVarIdents(pkg.TypesInfo, b)
			if len(vs) != 1 {
				return "", false
			}
			for v := range vs {
				vars[v] = true
			}
			lo, hi := boundsDirection(pkg.TypesInfo, b)
			lower = lower || lo
			upper = upper || hi
		}
	}
	if len(vars) > 1 {
		return "", false
	}
	for v := range vars {
		cmpVar = v
	}
	cases := 0
	hasDefault := false
	for _, stmt := range s.Body.List {
		cc := stmt.(*ast.CaseClause)
		if cc.List != nil {
			cases++
		} else {
			hasDefault = true
		}
		block := &ast.BlockStmt{List: cc.Body}
		if branchBounds(pkg.TypesInfo, block, ident) {
			continue
		}
		// Range-gated write: only the default clause sees values that
		// survived every bound check; assigning it a conversion of the
		// two-side-bounded compared var keeps ident bounded.
		if cc.List == nil && cmpVar != ident && lower && upper &&
			branchBoundsGated(pkg.TypesInfo, block, ident, cmpVar) {
			continue
		}
		return "", false
	}
	if cases == 0 {
		return "", false
	}
	// Range-gated mode needs a default: without it an unmatched cv leaves
	// ident's previous value in place, which is not provably bounded. In
	// self-sanitize mode the pass-through keeps the already-in-range ident.
	if cmpVar != ident && !hasDefault {
		return "", false
	}
	if cmpVar != ident {
		return fmt.Sprintf("sanitize-switch on %s range-gated by %s (%d case(s))", ident, cmpVar, cases), true
	}
	return fmt.Sprintf("sanitize-switch on %s (%d case(s))", ident, cases), true
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
// are variables the bound is ambiguous and neither flag is set.
func boundsDirection(info *types.Info, b *ast.BinaryExpr) (lower, upper bool) {
	lv := len(exprVarIdents(info, b.X)) > 0
	rv := len(exprVarIdents(info, b.Y)) > 0
	if lv == rv {
		return false, false
	}
	op := b.Op
	if rv {
		// Mirror the comparison so the variable is on the left.
		op = mirrorOp(op)
	}
	switch op {
	case token.LSS, token.LEQ:
		return true, false // v < x: passing values are >= x
	case token.GTR, token.GEQ:
		return false, true // v > x: passing values are <= x
	}
	return false, false
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
