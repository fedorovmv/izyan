package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"

	"golang.org/x/tools/go/packages"

	"example.com/vuln-analyzer/internal/domain"
)

// maxTraceHops bounds how far argument provenance follows identifiers into
// callers. Deeper chains resolve to UNKNOWN (a limitation), not a guess.
const maxTraceHops = 2

// TraceArgument classifies the data origin of the argument at argIndex of
// the call site (File+Line locate the call expression).
func (ix *Index) TraceArgument(ctx context.Context, site domain.CallSite, argIndex int) (domain.DataFlow, []domain.Evidence, error) {
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
	if argIndex >= len(call.Args) {
		return flow, nil, fmt.Errorf("call site has %d args, arg %d requested", len(call.Args), argIndex)
	}
	origin, why := ix.classify(pkg, enc, call.Args[argIndex], 0)
	flow.Origin = origin
	flow.Summary = why
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
		return ix.classifySelector(pkg, e, depth)
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
	obj := pkg.TypesInfo.ObjectOf(id)
	if obj == nil {
		return domain.OriginUnknown, fmt.Sprintf("unresolved identifier %s", id.Name)
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
	// local var: find dominating assignment inside the function
	if rhs := findLocalAssign(enc, obj); rhs != nil {
		o, why := ix.classify(pkg, enc, rhs, depth)
		return o, fmt.Sprintf("local %s <- %s", id.Name, why)
	}
	return domain.OriginUnknown, fmt.Sprintf("identifier %s without resolvable initializer", id.Name)
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
func (ix *Index) classifySelector(pkg *packages.Package, e *ast.SelectorExpr, depth int) (domain.DataOrigin, string) {
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
	// transparent selector: classify base
	return ix.classify(pkg, nil, e.X, depth)
}

func isHTTPRequest(t types.Type) bool {
	s := t.String()
	return strings.HasSuffix(s, "net/http.Request") || strings.HasSuffix(s, "*net/http.Request")
}

// classifyCall handles calls: known source functions, transformations, or
// opaque functions.
func (ix *Index) classifyCall(pkg *packages.Package, enc *ast.FuncDecl, call *ast.CallExpr, depth int) (domain.DataOrigin, string) {
	obj := calleeObject(pkg.TypesInfo, call.Fun)
	if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil {
		key := fn.Pkg().Path() + "." + fn.Name()
		if o, ok := knownSourceFuncs[key]; ok {
			return o, key
		}
		if sig, ok2 := fn.Type().(*types.Signature); ok2 && sig.Recv() != nil && isHTTPRequest(sig.Recv().Type()) {
			return domain.OriginExternalUntrusted, "method on *http.Request"
		}
		return domain.OriginUnknown, fmt.Sprintf("opaque call %s", key)
	}
	// builtins / transformations propagate the origin of their input
	if len(call.Args) > 0 {
		return ix.classify(pkg, enc, call.Args[0], depth)
	}
	return domain.OriginUnknown, "unresolvable call"
}

// knownSourceFuncs maps pkgpath.Func to a data origin. Extend as needed —
// this is provenance, not pattern matching for verdicts.
var knownSourceFuncs = map[string]domain.DataOrigin{
	"os.Getenv":                domain.OriginConfiguration,
	"os.ReadFile":              domain.OriginConfiguration,
	"io/ioutil.ReadFile":       domain.OriginConfiguration,
	"flag.String":              domain.OriginConfiguration,
	"flag.Int":                 domain.OriginConfiguration,
	"flag.Bool":                domain.OriginConfiguration,
	"flag.Parse":               domain.OriginConfiguration,
	"fmt.Sscanf":               domain.OriginUnknown,
	"os.Open":                  domain.OriginConfiguration,
	"net/http.Get":             domain.OriginExternalUntrusted,
	"net/http.Post":            domain.OriginExternalUntrusted,
	"net/http.ReadRequest":     domain.OriginExternalUntrusted,
	"io.ReadAll":               domain.OriginUnknown, // depends on arg
	"bufio.NewScanner":         domain.OriginUnknown,
	"encoding/json.Unmarshal":  domain.OriginUnknown,
	"encoding/json.NewDecoder": domain.OriginUnknown,
}

// traceParam resolves an argument bound to an enclosing function parameter by
// looking at the callers of that function (one hop).
func (ix *Index) traceParam(pkg *packages.Package, enc *ast.FuncDecl, v *types.Var, depth int) (domain.DataOrigin, string) {
	if depth >= maxTraceHops || enc == nil || enc.Name == nil {
		return domain.OriginUnknown, fmt.Sprintf("parameter %s of %s: caller tracing depth exceeded", v.Name(), enc.Name)
	}
	// find which parameter index this is
	paramIdx := -1
	idx := 0
	for _, f := range enc.Type.Params.List {
		for _, n := range f.Names {
			if n.Name == v.Name() {
				paramIdx = idx
			}
			idx++
		}
	}
	if paramIdx < 0 {
		return domain.OriginUnknown, "parameter index not found"
	}
	// callers of enclosing function
	var encRef domain.SymbolRef
	if pkg.Types != nil {
		encRef = domain.SymbolRef{Package: pkg.PkgPath, Symbol: enc.Name.Name}
		if enc.Recv != nil && len(enc.Recv.List) > 0 {
			// method: include receiver type name
			t := pkg.TypesInfo.TypeOf(enc.Recv.List[0].Type)
			if t != nil {
				encRef.Symbol = recvTypeName(t) + "." + enc.Name.Name
			}
		}
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

// FindValidations locates guard statements in the enclosing function that
// constrain the argument before the sink call.
func (ix *Index) FindValidations(ctx context.Context, site domain.CallSite, argIndex int) ([]domain.Validation, []domain.Evidence, error) {
	var vals []domain.Validation
	var ev []domain.Evidence
	if err := ix.load(ctx); err != nil {
		return nil, nil, err
	}
	call, enc, pkg, err := ix.callAt(site)
	if err != nil {
		return nil, nil, err
	}
	if enc == nil || enc.Body == nil || argIndex >= len(call.Args) {
		return nil, nil, nil
	}
	argIdent := argIdentifier(call.Args[argIndex])
	for _, stmt := range enc.Body.List {
		if stmt.Pos() >= call.Pos() {
			break
		}
		v := stmtValidation(ix, pkg, stmt, argIdent)
		if v != nil {
			p := ix.fset.Position(stmt.Pos())
			vals = append(vals, *v)
			vals[len(vals)-1].File = p.Filename
			vals[len(vals)-1].Line = p.Line
		}
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
	}
	return ""
}

// stmtValidation inspects a statement before the sink for constraints on
// ident: `if <pred on ident> { return/panic }` or `ident = sanitize(ident)`.
func stmtValidation(ix *Index, pkg *packages.Package, stmt ast.Stmt, ident string) *domain.Validation {
	switch s := stmt.(type) {
	case *ast.IfStmt:
		if ident == "" || !exprMentions(s.Cond, ident) {
			return nil
		}
		if terminates(s.Body) {
			condSrc, _ := ix.nodeSource(s.Cond)
			return &domain.Validation{Property: condSrc}
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
