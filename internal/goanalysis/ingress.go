package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"

	"example.com/vuln-analyzer/internal/domain"
)

// ingress.go — the ingress-closure completeness strategy (backlog B26,
// dev/specs/incremental-analysis-value-spec.md §5.3–5.5).
//
// Instead of proving something about individual affected sinks, the
// inventory enumerates every way data can enter the product-reachable
// dependency cone:
//
//   - boundary entries: product call sites into the module — every
//     argument, method receiver and the writable state of passed objects;
//   - autonomous sources inside the cone: knowledge-base source calls
//     (env/file/network/db/service), channel receives, reads of mutable
//     package vars, callbacks dispatching outside the module, and calls
//     into other dependency modules;
//   - completeness blockers: spots where the inventory itself cannot be
//     proven closed — function values escaping the call graph, opaque
//     callees in cone code, reflective invocation, plugins/linkname.
//
// A FALSE claim is allowed only for a complete closure whose recorded
// elements all resolve to CONSTANT/GENERATED origins. Reaches is
// diagnostic only: an empty reach set does not exclude an inventoried item.
// Anything else stays UNKNOWN.

// ingressEntry is one product→module boundary call site.
type ingressEntry struct {
	site      domain.CallSite
	calleeKey string // moduleEdges callee-key form
	call      *ast.CallExpr
	enc       *ast.FuncDecl
	pkg       *packages.Package
}

type fnDeclRef struct {
	pkg  *packages.Package
	decl *ast.FuncDecl
	key  string // pkgpath.Name / pkgpath.Recv.Name — moduleEdges caller key
	fn   *types.Func
}

// depFeeder is a dependency package outside the analyzed module that
// imports a package of it — its init/body can feed module state without
// the product ever calling it.
type depFeeder struct {
	module  string
	pkgPath string
}

type ingressScan struct {
	ix       *Index
	module   string
	prodMod  string
	pkgMod   map[string]string
	subjects map[string]bool
	modPkgs  []*packages.Package

	edges      map[string]map[string]bool
	decls      map[string]fnDeclRef
	initDecls  []fnDeclRef
	cone       map[string]bool
	entries    []ingressEntry
	feeders    []depFeeder
	extraDecls []fnDeclRef

	items    []domain.IngressItem
	blockers []string

	varSeen     map[string]bool
	scanned     map[*ast.FuncDecl]bool
	litSeen     map[*ast.FuncLit]bool
	callers     map[string][]string  // callee key -> caller decl keys (inverted edges)
	methodCalls map[string][]selCall // method name -> call sites inside module code
	ifaceCache  map[string][]string  // iface key+method -> outside-module impls
	varReads    []varRead
	varWrites   map[*types.Var]*varWriteSet
}

// IngressInventory builds the coverage set of the ingress-closure
// strategy for module. subjects mark which boundary entries can deliver
// payload toward an affected symbol. hops is the caller-climb budget for
// origin classification — callers pass the verification budget so
// collection and re-verification see the same scope.
func (ix *Index) IngressInventory(ctx context.Context, module string, subjects []domain.SymbolRef, hops int) (domain.IngressClosure, []domain.Evidence, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	cl := domain.IngressClosure{Module: module}
	if err := ix.load(ctx); err != nil {
		return cl, nil, err
	}
	ix.hopLimit = hops
	ix.traceSeen = map[types.Object]bool{}
	ix.paramSeen = map[string]bool{}
	ix.paramCache = map[string]classifyResult{}
	ix.classifyCache = map[classifyKey]classifyResult{}
	ix.funcDeclCache = map[string]funcDeclResult{}
	ix.evalBudget = maxEvalBudget
	defer func() {
		ix.hopLimit = 0
		ix.traceSeen = nil
		ix.paramSeen = nil
		ix.paramCache = nil
		ix.classifyCache = nil
		ix.funcDeclCache = nil
		ix.evalBudget = 0
	}()

	modPkgs, err := ix.loadExtra(ctx, module+"/...")
	if err != nil {
		cl.Blockers = append(cl.Blockers, fmt.Sprintf("module source load failed: %v", err))
		return cl, nil, nil
	}
	releasePin := ix.pinExtraScoped(module + "/...")
	defer releasePin()
	if _, err := ix.depImporters(ctx); err != nil {
		cl.Blockers = append(cl.Blockers, fmt.Sprintf("dependency module map failed: %v", err))
		return cl, nil, nil
	}

	s := &ingressScan{
		ix:         ix,
		module:     module,
		pkgMod:     ix.pkgModules,
		subjects:   map[string]bool{},
		modPkgs:    modPkgs,
		decls:      map[string]fnDeclRef{},
		cone:       map[string]bool{},
		varSeen:    map[string]bool{},
		scanned:    map[*ast.FuncDecl]bool{},
		litSeen:    map[*ast.FuncLit]bool{},
		ifaceCache: map[string][]string{},
	}
	for _, p := range ix.pkgs {
		if s.prodMod == "" && ix.pkgModules[p.PkgPath] != "" {
			s.prodMod = ix.pkgModules[p.PkgPath]
		}
	}
	for _, subj := range subjects {
		s.subjects[subj.Package+"."+subj.Symbol] = true
	}
	s.edges, _ = ix.moduleEdges(modPkgs, module)
	s.indexDecls(modPkgs)
	s.findEntries()
	s.findFeeders(modPkgs)
	s.inventoryEntries()
	s.buildCone()
	s.markReaches()
	s.scanCone()
	s.emitVarItems()
	s.annotateReaches()

	cl.Items = s.items
	cl.Blockers = s.blockers
	cl.Complete = len(s.blockers) == 0

	ev := []domain.Evidence{{
		Kind:    domain.EvidenceDataFlow,
		Quality: domain.QualityDeterministic,
		Source:  "source index: ingress closure inventory",
		Tool:    "goanalysis.Index.IngressInventory",
		Content: s.summary(),
	}}
	return cl, ev, nil
}

func (s *ingressScan) summary() string {
	var safe, unsafe, unknown int
	for _, it := range s.items {
		switch it.Origin {
		case domain.OriginConstant, domain.OriginGenerated:
			safe++
		case domain.OriginExternalUntrusted, domain.OriginExternalAuthenticated,
			domain.OriginConfiguration, domain.OriginDatabase, domain.OriginInternalService:
			unsafe++
		default:
			unknown++
		}
	}
	return fmt.Sprintf("ingress closure over %s: %d boundary entrie(s), %d item(s) "+
		"(%d safe / %d unsafe / %d unresolved), %d cone function(s), complete=%t; blockers: %s",
		s.module, len(s.entries), len(s.items), safe, unsafe, unknown,
		len(s.cone), len(s.blockers) == 0, strings.Join(s.blockers, "; "))
}

// indexDecls maps every module function declaration under its
// moduleEdges caller key. File-level blockers (plugin loading,
// go:linkname aliasing) are collected along the way — they can inject
// code or calls the inventory never sees.
func (s *ingressScan) indexDecls(pkgs []*packages.Package) {
	for _, pkg := range pkgs {
		for _, f := range pkg.Syntax {
			for _, imp := range f.Imports {
				if strings.Trim(imp.Path.Value, `"`) == "plugin" {
					pos := s.ix.fset.Position(imp.Pos())
					s.blockers = append(s.blockers, fmt.Sprintf(
						"%s imports plugin at %s:%d — dynamically loaded code bypasses the inventory",
						pkg.PkgPath, pos.Filename, pos.Line))
				}
			}
			for _, grp := range f.Comments {
				for _, c := range grp.List {
					if strings.Contains(c.Text, "go:linkname") {
						pos := s.ix.fset.Position(c.Pos())
						s.blockers = append(s.blockers, fmt.Sprintf(
							"%s has go:linkname at %s:%d — symbol aliasing bypasses the call graph",
							pkg.PkgPath, pos.Filename, pos.Line))
					}
				}
			}
			for _, d := range f.Decls {
				fd, ok := d.(*ast.FuncDecl)
				if !ok || fd.Name == nil {
					continue
				}
				key := pkg.PkgPath + "." + fd.Name.Name
				if fd.Recv != nil && len(fd.Recv.List) > 0 {
					key = pkg.PkgPath + "." + recvDeclName(fd.Recv.List[0].Type) + "." + fd.Name.Name
				}
				fn, _ := pkg.TypesInfo.Defs[fd.Name].(*types.Func)
				ref := fnDeclRef{pkg: pkg, decl: fd, key: key, fn: fn}
				s.decls[key] = ref
				if fd.Name.Name == "init" && fd.Recv == nil {
					s.initDecls = append(s.initDecls, ref)
				}
			}
		}
	}
}

// findEntries scans product packages for boundary call sites (callee
// owned by the module), module-function escapes (references outside call
// position — the function becomes invocable with un-inventoried
// arguments), and records other dependency modules the product calls so
// findFeeders can check whether they can reach into the module.
func (s *ingressScan) findEntries() {
	for _, pkg := range s.ix.pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			// Nodes that appear in a call's Fun position are call sites,
			// not value references — including the .Sel identifier of a
			// `pkg.F(...)` selector, which is a separate node.
			funSet := map[ast.Node]bool{}
			var enc *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				switch v := n.(type) {
				case *ast.FuncDecl:
					enc = v
					return true
				case *ast.CallExpr:
					funSet[v.Fun] = true
					if sel, ok := v.Fun.(*ast.SelectorExpr); ok {
						funSet[sel.Sel] = true
					}
					obj := calleeObject(info, v.Fun)
					if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil {
						p := fn.Pkg().Path()
						if s.inModule(p) {
							s.entries = append(s.entries, ingressEntry{
								site:      s.ix.siteOf(pkg, enc, v),
								calleeKey: s.calleeKey(fn),
								call:      v, enc: enc, pkg: pkg,
							})
						}
					}
					return true
				}
				if funSet[n] {
					return true
				}
				var obj types.Object
				switch e := n.(type) {
				case *ast.Ident:
					obj = info.ObjectOf(e)
				case *ast.SelectorExpr:
					if sl, ok := info.Selections[e]; ok {
						obj = sl.Obj()
					} else {
						obj = info.ObjectOf(e.Sel)
					}
				default:
					return true
				}
				// Module function used outside a call position — a func
				// value can be invoked from anywhere with arguments this
				// inventory never classified.
				if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil && s.inModule(fn.Pkg().Path()) {
					pos := s.ix.fset.Position(n.Pos())
					s.blockers = append(s.blockers, fmt.Sprintf(
						"module function %s used as value at %s:%d — callable with un-inventoried arguments",
						fn.Pkg().Path()+"."+fn.Name(), pos.Filename, pos.Line))
				}
				return true
			})
		}
	}
}

// findFeeders flags dependency packages outside the module that import
// one of its packages — their init/functions can call into the module
// and feed its state, making writer sets not enumerable from the
// product. Product importers and same-module packages are excluded.
func (s *ingressScan) findFeeders(modPkgs []*packages.Package) {
	for _, p := range modPkgs {
		for _, im := range s.ix.importers[p.PkgPath] {
			if im.module == s.module || im.module == s.prodMod || im.module == "" {
				continue
			}
			s.feeders = append(s.feeders, depFeeder{module: im.module, pkgPath: im.path})
		}
	}
	seen := map[string]bool{}
	var uniq []depFeeder
	for _, fd := range s.feeders {
		if !seen[fd.pkgPath] {
			seen[fd.pkgPath] = true
			uniq = append(uniq, fd)
		}
	}
	s.feeders = uniq
	for _, fd := range s.feeders {
		s.addItem(domain.IngressItem{
			Kind:   domain.IngressIntermediateDep,
			Origin: domain.OriginUnknown,
			Detail: fmt.Sprintf("dependency module %s (package %s) imports %s — its init/internal calls can feed module state outside the product boundary",
				fd.module, fd.pkgPath, s.module),
		})
	}
}

func (s *ingressScan) inModule(pkgPath string) bool {
	return pkgPath == s.module || strings.HasPrefix(pkgPath, s.module+"/")
}

// calleeKey renders fn the way moduleEdges names callees.
func (s *ingressScan) calleeKey(fn *types.Func) string {
	p := fn.Pkg().Path() + "." + fn.Name()
	if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
		p = fn.Pkg().Path() + "." + recvTypeName(sig.Recv().Type()) + "." + fn.Name()
	}
	return p
}

// inventoryEntries classifies every argument, method receiver and
// writable object-state piece of each boundary entry.
func (s *ingressScan) inventoryEntries() {
	for _, e := range s.entries {
		for i, arg := range e.call.Args {
			o, w := s.ix.classify(e.pkg, e.enc, arg, 0)
			s.addItem(domain.IngressItem{
				CallSite: e.site,
				Kind:     domain.IngressBoundaryArg,
				Callee:   e.calleeKey,
				Arg:      i,
				Origin:   o,
				Detail:   w,
			})
			s.objectState(e, arg, i)
			d := fnDeclRef{pkg: e.pkg, decl: e.enc, key: e.calleeKey}
			s.scanBody(e.pkg, d, arg, func(target fnDeclRef) {
				s.extraDecls = append(s.extraDecls, target)
			})
		}
		if sel, ok := e.call.Fun.(*ast.SelectorExpr); ok {
			if _, isSel := e.pkg.TypesInfo.Selections[sel]; isSel {
				o, w := s.ix.classify(e.pkg, e.enc, sel.X, 0)
				s.addItem(domain.IngressItem{
					CallSite: e.site,
					Kind:     domain.IngressBoundaryReceiver,
					Callee:   e.calleeKey,
					Arg:      -1,
					Origin:   o,
					Detail:   "receiver: " + w,
				})
				s.objectState(e, sel.X, -1)
				d := fnDeclRef{pkg: e.pkg, decl: e.enc, key: e.calleeKey}
				s.scanBody(e.pkg, d, sel.X, func(target fnDeclRef) {
					s.extraDecls = append(s.extraDecls, target)
				})
			}
		}
	}
}

// objectState inventories writes to the state of an object that crosses
// the boundary: `v.F = x` / `v[k] = x` assignments in the calling
// function the callee can read off the passed object.
func (s *ingressScan) objectState(e ingressEntry, expr ast.Expr, argIdx int) {
	if u, ok := expr.(*ast.UnaryExpr); ok && u.Op == token.AND {
		expr = u.X
	}
	id, ok := expr.(*ast.Ident)
	if !ok || e.pkg.TypesInfo == nil || e.enc == nil {
		return
	}
	obj, ok := e.pkg.TypesInfo.ObjectOf(id).(*types.Var)
	if !ok {
		return
	}
	info := e.pkg.TypesInfo
	ast.Inspect(e.enc.Body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			// writes reaching the object: v.F =, v[k] =, v.F[k] =
			if _, isIdent := lhs.(*ast.Ident); isIdent {
				continue // whole-object rebind — classify on arg covers it
			}
			if base := lhsBaseIdent(info, lhs); base != nil && sameObject(info.ObjectOf(base), obj) {
				var rhs ast.Expr
				if i < len(as.Rhs) {
					rhs = as.Rhs[i]
				} else if len(as.Rhs) == 1 {
					rhs = as.Rhs[0]
				}
				if rhs == nil {
					continue
				}
				o, w := s.ix.classify(e.pkg, e.enc, rhs, 1)
				pos := s.ix.fset.Position(as.Pos())
				s.addItem(domain.IngressItem{
					CallSite: e.site,
					Kind:     domain.IngressObjectState,
					Callee:   e.calleeKey,
					Arg:      argIdx,
					Origin:   o,
					Detail:   fmt.Sprintf("write %s at %s:%d: %s", lhsText(lhs), pos.Filename, pos.Line, w),
				})
			}
		}
		return true
	})
}

// lhsBaseIdent returns the base identifier of an LHS expression —
// v in v.F = x, v[k] = x, (*v).F = x — nil when the LHS is not
// rooted at an identifier.
func lhsBaseIdent(info *types.Info, e ast.Expr) *ast.Ident {
	switch v := e.(type) {
	case *ast.Ident:
		return v
	case *ast.SelectorExpr:
		return lhsBaseIdent(info, v.X)
	case *ast.IndexExpr, *ast.IndexListExpr, *ast.SliceExpr:
		return lhsBaseIdent(info, childExpr(v))
	case *ast.StarExpr:
		return lhsBaseIdent(info, v.X)
	case *ast.ParenExpr:
		return lhsBaseIdent(info, v.X)
	}
	return nil
}

func lhsText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		if b := lhsBaseIdent(nil, v); b != nil {
			return b.Name + "." + v.Sel.Name
		}
	case *ast.IndexExpr:
		if b := lhsBaseIdent(nil, v); b != nil {
			return b.Name + "[...]"
		}
	case *ast.Ident:
		return v.Name
	}
	return "?"
}

// buildCone computes the product-reachable function set inside the
// module: BFS from boundary callee keys over moduleEdges.
func (s *ingressScan) buildCone() {
	var queue []string
	for _, e := range s.entries {
		if !s.cone[e.calleeKey] {
			s.cone[e.calleeKey] = true
			queue = append(queue, e.calleeKey)
		}
	}
	for len(queue) > 0 {
		k := queue[len(queue)-1]
		queue = queue[:len(queue)-1]
		for n := range s.edges[k] {
			if !s.cone[n] {
				s.cone[n] = true
				queue = append(queue, n)
			}
		}
	}
}

// markReaches annotates boundary items with the subject keys their entry
// can reach through the cone — an item whose entry reaches no subject is
// excluded as provably not payload.
func (s *ingressScan) markReaches() {
	reaches := map[*ingressEntry][]string{}
	for i := range s.entries {
		e := &s.entries[i]
		var r []string
		for subj := range s.subjects {
			if s.cone[subj] && e.calleeKey == subj {
				r = append(r, subj)
				continue
			}
			if bfsChain(s.edges, e.calleeKey, subj) != nil {
				r = append(r, subj)
			}
		}
		sort.Strings(r)
		reaches[e] = r
	}
	for i := range s.items {
		for e, r := range reaches {
			if s.items[i].Callee == e.calleeKey && s.items[i].Line == e.site.Line && s.items[i].File == e.site.File {
				s.items[i].Reaches = r
				break
			}
		}
	}
}

// scanCone walks every cone function plus init bodies for autonomous
// sources and completeness blockers.
func (s *ingressScan) scanCone() {
	queue := map[*ast.FuncDecl]bool{}
	var order []fnDeclRef
	push := func(d fnDeclRef) {
		if s.scanned[d.decl] || queue[d.decl] {
			return
		}
		queue[d.decl] = true
		order = append(order, d)
	}
	for key := range s.cone {
		if d, ok := s.decls[key]; ok {
			push(d)
		}
	}
	for _, d := range s.extraDecls {
		push(d)
	}
	// init() bodies run only for packages actually linked into the
	// product binary — the product's transitive import closure. Module
	// packages the product never imports (tools, codegen mains) cannot
	// feed runtime state and are not inventoried.
	reach := s.importedByProduct()
	for _, d := range s.initDecls {
		if reach[d.pkg.PkgPath] {
			push(d)
		}
	}
	for _, pkg := range s.modPkgs {
		if !reach[pkg.PkgPath] || pkg.TypesInfo == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			for _, decl := range f.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, value := range vs.Values {
						name := "package initializer"
						fd := &ast.FuncDecl{Name: &ast.Ident{Name: name}, Type: &ast.FuncType{}, Body: &ast.BlockStmt{}}
						d := fnDeclRef{pkg: pkg, decl: fd, key: pkg.PkgPath + "." + name}
						s.scanBody(pkg, d, value, push)
					}
				}
			}
		}
	}
	for len(order) > 0 {
		d := order[len(order)-1]
		order = order[:len(order)-1]
		delete(queue, d.decl)
		if s.scanned[d.decl] {
			continue
		}
		s.scanned[d.decl] = true
		s.scanDecl(d, push)
	}
}

// scanDecl inspects one function body for ingress elements.
func (s *ingressScan) scanDecl(d fnDeclRef, push func(fnDeclRef)) {
	if d.decl == nil || d.decl.Body == nil {
		s.blockers = append(s.blockers, fmt.Sprintf("body unavailable for %s — effects are not inventoried", d.key))
		return
	}
	s.scanBody(d.pkg, d, d.decl, push)
}

// scanBody inspects a syntax subtree for ingress elements — shared by
// declared functions and by package-level function literals stored in
// vars/fields (code that runs on dispatch but sits outside any FuncDecl).
func (s *ingressScan) scanBody(pkg *packages.Package, d fnDeclRef, root ast.Node, push func(fnDeclRef)) {
	info := pkg.TypesInfo
	if info == nil {
		return
	}
	ast.Inspect(root, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			s.scanCall(pkg, d, v, push)
		case *ast.UnaryExpr:
			if v.Op == token.ARROW {
				pos := s.ix.fset.Position(v.Pos())
				s.addItem(domain.IngressItem{
					CallSite: s.siteAt(pkg, d.decl, v.Pos()),
					Kind:     domain.IngressConeSource,
					Origin:   domain.OriginUnknown,
					Detail:   fmt.Sprintf("channel receive at %s:%d — senders outside the cone are not enumerable", pos.Filename, pos.Line),
				})
			}
		case *ast.RangeStmt:
			if info.TypeOf(v.X) != nil {
				if _, isChan := info.TypeOf(v.X).Underlying().(*types.Chan); isChan {
					s.addItem(domain.IngressItem{
						CallSite: s.siteAt(pkg, d.decl, v.Pos()),
						Kind:     domain.IngressConeSource,
						Origin:   domain.OriginUnknown,
						Detail:   "range over channel — senders outside the cone are not enumerable",
					})
				}
			}
		case *ast.AssignStmt:
			// Writes whose target is not rooted at an identifier —
			// `*(*T)(unsafe.Pointer(p)) = x`, `v.f().x = y` — elude the
			// writer enumeration. They cannot conjure a new source: the
			// written value is still a classifiable expression, so the
			// origin check covers the data; the target just stays opaque.
			for i, lhs := range v.Lhs {
				if lhsBaseIdent(info, lhs) != nil || !exprHasCall(lhs) {
					continue
				}
				var rhs ast.Expr
				if i < len(v.Rhs) {
					rhs = v.Rhs[i]
				} else if len(v.Rhs) == 1 {
					rhs = v.Rhs[0]
				}
				if rhs == nil {
					continue
				}
				o, w := s.ix.classify(pkg, d.decl, rhs, 0)
				if o != domain.OriginConstant && o != domain.OriginGenerated {
					s.addItem(domain.IngressItem{
						CallSite: s.siteAt(pkg, d.decl, v.Pos()),
						Kind:     domain.IngressConeSource,
						Origin:   o,
						Detail:   "write through opaque target (unsafe/reflect store): " + w,
					})
				}
			}
		case *ast.Ident:
			s.checkPkgVar(pkg, d, v)
		case *ast.SelectorExpr:
			s.checkSelVar(pkg, d, v)
		}
		return true
	})
}

// exprHasCall reports whether e contains a call expression (i.e. the
// expression's result is produced by code, not a plain data reference).
func exprHasCall(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if _, ok := n.(*ast.CallExpr); ok {
			found = true
		}
		return !found
	})
	return found
}

// scanCall classifies a call inside cone code.
func (s *ingressScan) scanCall(pkg *packages.Package, d fnDeclRef, call *ast.CallExpr, push func(fnDeclRef)) {
	info := pkg.TypesInfo
	// Type conversions are not calls: `[]byte(x)`, `T(v)`.
	if tv, ok := info.Types[call.Fun]; ok && tv.IsType() {
		return
	}
	obj := calleeObject(info, call.Fun)
	switch o := obj.(type) {
	case *types.Builtin:
		if o.Name() == "recover" {
			s.addItem(domain.IngressItem{
				CallSite: s.siteAt(pkg, d.decl, call.Pos()),
				Kind:     domain.IngressConeSource,
				Callee:   "builtin.recover",
				Origin:   domain.OriginUnknown,
				Detail:   "recover may return a panic value supplied outside the inventoried cone",
			})
		}
		return
	case *types.TypeName:
		return
	case *types.Func:
		// Interface dispatch: implementations outside the module are
		// product/dep callbacks the inventory cannot trace — flagged
		// regardless of where the interface itself is declared.
		s.ifaceOutOfModule(pkg, d, call, o)
		if o.Pkg() == nil {
			return
		}
		p := o.Pkg().Path()
		if s.inModule(p) {
			// Internal edge — already part of the graph for cone members;
			// for init/reflect-pushed decls it extends the scan.
			if tgt, ok := s.decls[s.calleeKey(o)]; ok {
				push(tgt)
			}
			return
		}
		if m := s.pkgMod[p]; m != "" {
			if m == s.prodMod {
				s.addItem(domain.IngressItem{
					CallSite: s.siteAt(pkg, d.decl, call.Pos()),
					Kind:     domain.IngressConeSource,
					Callee:   s.calleeKey(o),
					Origin:   domain.OriginUnknown,
					Detail:   "cone calls back into product code — callback results are not provable",
				})
				return
			}
			s.addItem(domain.IngressItem{
				CallSite: s.siteAt(pkg, d.decl, call.Pos()),
				Kind:     domain.IngressConeSource,
				Callee:   s.calleeKey(o),
				Origin:   domain.OriginUnknown,
				Detail:   fmt.Sprintf("call into dependency module %s — its internals are not inventoried", m),
			})
			return
		}
		// stdlib or unresolved owner — knowledge-base semantics.
		s.scanStdlibCall(pkg, d, call, o, push)
	default:
		// No callable object: function value, funclit-var or dynamic
		// call. Inside a FuncLit the callee is the literal itself and its
		// body is scanned inline.
		if _, lit := call.Fun.(*ast.FuncLit); lit {
			return
		}
		s.funcValueCall(pkg, d, call, obj, push)
	}
}

// funcValueCall resolves a call through a variable/field instead of a
// name — `parser.read_handler(...)`, `f()` where f is a func-typed var.
// The dispatch target set is the set of functions ever written into
// that var/field; each target is scanned. An unresolved or empty target
// set means the call's real callee is invisible — a blocker, since that
// code could read sources the inventory never inspected.
// rhsRef is one write-site expression that may produce the called
// function value — a static function name, a literal body, or another
// func-valued variable whose own writes must be chased.
type rhsRef struct {
	pkg  *packages.Package
	enc  *ast.FuncDecl
	expr ast.Expr
}

func (s *ingressScan) funcValueCall(pkg *packages.Package, d fnDeclRef, call *ast.CallExpr, obj types.Object, push func(fnDeclRef)) {
	pos := s.ix.fset.Position(call.Pos())
	where := fmt.Sprintf("%s at %s:%d", d.key, pos.Filename, pos.Line)
	var rhses []rhsRef
	switch v := obj.(type) {
	case *types.Var:
		switch {
		case v.IsField():
			// Field func value: enumerate every write into the field.
			for _, w := range s.ix.fieldWriteSites(v) {
				rhses = append(rhses, rhsRef{w.pkg, w.enc, w.rhs})
			}
		case isParam(d.decl, v):
			// Callback parameter: every caller of the enclosing decl
			// supplies a candidate implementation.
			rhses = s.paramFuncValues(pkg, d, v)
		case isPackageVar(v):
			var open bool
			var why string
			rhses, open, why = s.packageFuncValues(v)
			if open {
				s.blockers = append(s.blockers, fmt.Sprintf(
					"func-value call in %s — package var %s has unclosed writes or escapes: %s",
					where, v.Name(), why))
			}
		default:
			for _, e := range localAssigns(d.decl, v) {
				rhses = append(rhses, rhsRef{pkg, d.decl, e})
			}
			// Package-level func var: initializer is a GenDecl value in
			// the var's own package, which may differ from the caller's.
			if len(rhses) == 0 {
				if vp := s.pkgOf(v); vp != nil {
					if init := findVarInit(vp, v); init != nil {
						rhses = append(rhses, rhsRef{vp, nil, init})
					}
				}
			}
		}
	case nil:
		s.blockers = append(s.blockers, fmt.Sprintf(
			"unresolved call in %s — callee not visible to static analysis (%s)", where, funText(call.Fun)))
		return
	default:
		s.blockers = append(s.blockers, fmt.Sprintf(
			"dynamic call (%T) in %s — callee set unbounded", obj, where))
		return
	}
	if len(rhses) == 0 {
		s.blockers = append(s.blockers, fmt.Sprintf(
			"func-value call in %s — no writes to the callee var/field found (%s)", where, funText(call.Fun)))
		return
	}
	seen := map[ast.Expr]bool{}
	for i := 0; i < len(rhses); i++ {
		r := rhses[i]
		if r.expr == nil || seen[r.expr] {
			continue
		}
		seen[r.expr] = true
		// Function literal: its body is cone code executed on dispatch.
		// Literals nested in a scanned decl are covered by its walk;
		// package-level ones are scanned once here — wrapped in a
		// synthetic FuncDecl so local-assignment and param resolution
		// see the literal's own scope.
		if lit, ok := ast.Unparen(r.expr).(*ast.FuncLit); ok {
			if r.enc == nil && !s.litSeen[lit] {
				s.litSeen[lit] = true
				fd := &ast.FuncDecl{
					Name: &ast.Ident{Name: d.key + "«lit»"},
					Type: lit.Type,
					Body: lit.Body,
				}
				s.scanBody(r.pkg, fnDeclRef{pkg: r.pkg, decl: fd, key: d.key}, lit.Body, push)
			}
			continue
		}
		// A call returning a function value: the callee's return
		// expressions are the func-producing sites. A nil return means
		// "no implementation" — the call site guards the dispatch, it
		// cannot hide code the inventory missed.
		if ce, ok := ast.Unparen(r.expr).(*ast.CallExpr); ok {
			if fn2, ok2 := calleeObject(r.pkg.TypesInfo, ce.Fun).(*types.Func); ok2 {
				for _, re := range s.returnExprs(r.pkg, fn2) {
					if id, ok3 := ast.Unparen(re.expr).(*ast.Ident); ok3 && id.Name == "nil" {
						continue
					}
					rhses = append(rhses, re)
				}
				continue
			}
		}
		// A nil write likewise contributes no dispatch target.
		if id, ok := ast.Unparen(r.expr).(*ast.Ident); ok && id.Name == "nil" {
			continue
		}
		// Alias to another func-valued var: chase its writes — locals in
		// the write site's function, package vars in their own package.
		if vv, ok := calleeObject(r.pkg.TypesInfo, r.expr).(*types.Var); ok {
			if isPackageVar(vv) {
				more, open, why := s.packageFuncValues(vv)
				rhses = append(rhses, more...)
				if open {
					s.blockers = append(s.blockers, fmt.Sprintf(
						"func-value alias in %s — package var %s has unclosed writes or escapes: %s",
						where, vv.Name(), why))
				}
				continue
			}
			for _, e := range localAssigns(r.enc, vv) {
				rhses = append(rhses, rhsRef{r.pkg, r.enc, e})
			}
			if vp := s.pkgOf(vv); vp != nil {
				if init := findVarInit(vp, vv); init != nil {
					rhses = append(rhses, rhsRef{vp, nil, init})
				}
			}
			continue
		}
		fn, ok := calleeObject(r.pkg.TypesInfo, r.expr).(*types.Func)
		if !ok || fn.Pkg() == nil {
			s.blockers = append(s.blockers, fmt.Sprintf(
				"func-value call in %s — callee write is not a static function (%s)", where, funText(r.expr)))
			return
		}
		p := fn.Pkg().Path()
		if s.inModule(p) {
			if tgt, ok := s.decls[s.calleeKey(fn)]; ok {
				push(tgt)
			}
			continue
		}
		if m := s.pkgMod[p]; m != "" {
			origin := domain.OriginUnknown
			detail := fmt.Sprintf("func value may dispatch into module %s — its internals are not inventoried", m)
			if m == s.prodMod {
				detail = "func value may dispatch back into product code — callback results are not provable"
			}
			s.addItem(domain.IngressItem{
				CallSite: s.siteAt(pkg, d.decl, call.Pos()),
				Kind:     domain.IngressConeSource,
				Callee:   s.calleeKey(fn),
				Origin:   origin,
				Detail:   detail,
			})
			continue
		}
		// stdlib target — e.g. a read handler bound to io.Reader paths.
		s.scanStdlibCall(pkg, d, call, fn, push)
	}
}

func (s *ingressScan) packageFuncValues(v *types.Var) (rhses []rhsRef, open bool, why string) {
	vp := s.pkgOf(v)
	if vp == nil {
		return nil, true, "declaring package source unavailable"
	}
	var reasons []string
	if v.Exported() {
		reasons = append(reasons, "exported package var may be assigned by external importers")
	}
	if init := findVarInit(vp, v); init != nil {
		rhses = append(rhses, rhsRef{pkg: vp, expr: init})
	} else {
		reasons = append(reasons, "no initializer")
	}
	scope := append(append([]*packages.Package{}, s.modPkgs...), s.ix.pkgs...)
	for _, pkg := range scope {
		if pkg == nil || pkg.TypesInfo == nil {
			continue
		}
		for _, file := range pkg.Syntax {
			var enc *ast.FuncDecl
			lhs := map[ast.Node]bool{}
			callFun := map[ast.Node]bool{}
			addressed := map[ast.Node]bool{}
			ast.Inspect(file, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.CallExpr:
					callFun[node.Fun] = true
					if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
						callFun[sel.Sel] = true
					}
				case *ast.AssignStmt:
					for _, e := range node.Lhs {
						ast.Inspect(e, func(n ast.Node) bool {
							if ident, ok := n.(*ast.Ident); ok && sameObject(pkg.TypesInfo.ObjectOf(ident), types.Object(v)) {
								lhs[ident] = true
							}
							return true
						})
					}
				case *ast.UnaryExpr:
					if node.Op == token.AND {
						ast.Inspect(node.X, func(n ast.Node) bool {
							if ident, ok := n.(*ast.Ident); ok && sameObject(pkg.TypesInfo.ObjectOf(ident), types.Object(v)) {
								addressed[ident] = true
							}
							return true
						})
					}
				}
				return true
			})
			ast.Inspect(file, func(n ast.Node) bool {
				if fd, ok := n.(*ast.FuncDecl); ok {
					enc = fd
				}
				switch node := n.(type) {
				case *ast.AssignStmt:
					for i, lhs := range node.Lhs {
						if !sameObject(packageVarExprObject(pkg.TypesInfo, lhs), types.Object(v)) {
							continue
						}
						var rhs ast.Expr
						switch {
						case i < len(node.Rhs):
							rhs = node.Rhs[i]
						case len(node.Rhs) == 1:
							rhs = node.Rhs[0]
						}
						if rhs == nil {
							reasons = append(reasons, "assignment result slot could not be identified")
							continue
						}
						rhses = append(rhses, rhsRef{pkg, enc, rhs})
						reasons = append(reasons, "package var is assigned outside its initializer")
					}
				case *ast.Ident:
					if !sameObject(pkg.TypesInfo.ObjectOf(node), types.Object(v)) || lhs[node] ||
						pkg.TypesInfo.Defs[node] != nil || callFun[node] {
						return true
					}
					if addressed[node] {
						reasons = append(reasons, "function value address is taken")
						return true
					}
					reasons = append(reasons, "function value escapes its package var")
				}
				return true
			})
		}
	}
	if len(rhses) == 0 {
		reasons = append(reasons, "no enumerable function target")
	}
	return rhses, len(reasons) > 0, strings.Join(deduplicateStrings(reasons), "; ")
}

func packageVarExprObject(info *types.Info, e ast.Expr) types.Object {
	switch e := ast.Unparen(e).(type) {
	case *ast.Ident:
		return info.ObjectOf(e)
	case *ast.SelectorExpr:
		if _, field := info.Selections[e]; !field {
			return info.ObjectOf(e.Sel)
		}
	}
	return nil
}

func (s *ingressScan) addUnknownCall(pkg *packages.Package, d fnDeclRef, call *ast.CallExpr,
	fn *types.Func, why string) {
	s.addItem(domain.IngressItem{
		CallSite: s.siteAt(pkg, d.decl, call.Pos()),
		Kind:     domain.IngressConeSource,
		Callee:   fn.Pkg().Path() + "." + fn.Name(),
		Origin:   domain.OriginUnknown,
		Detail:   why,
	})
}

func deduplicateStrings(values []string) []string {
	seen := map[string]bool{}
	out := values[:0]
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

// paramFuncValues resolves a func-valued parameter of d's declaration to
// the argument expressions callers supply: in-module callers through the
// inverted call graph, plus product boundary entries calling d directly.
func (s *ingressScan) paramFuncValues(pkg *packages.Package, d fnDeclRef, v *types.Var) []rhsRef {
	idx := -1
	i := 0
	if d.decl.Type.Params != nil {
		for _, f := range d.decl.Type.Params.List {
			for _, n := range f.Names {
				if n.Name == v.Name() && d.pkg.TypesInfo.ObjectOf(n) == types.Object(v) {
					idx = i
				}
				i++
			}
		}
	}
	if idx < 0 || d.fn == nil {
		return nil
	}
	var out []rhsRef
	for _, ck := range s.inEdges()[d.key] {
		cd, ok := s.decls[ck]
		if !ok || cd.pkg == nil || cd.pkg.TypesInfo == nil {
			continue
		}
		ast.Inspect(cd.decl.Body, func(n ast.Node) bool {
			ce, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if calleeObject(cd.pkg.TypesInfo, ce.Fun) == types.Object(d.fn) && idx < len(ce.Args) {
				out = append(out, rhsRef{cd.pkg, cd.decl, ce.Args[idx]})
			}
			return true
		})
	}
	// Interface-dispatched callers are not call-graph edges: a caller
	// doing `m.Range(f)` on an interface-typed m supplies the callback
	// for every implementation the interface admits. Enumerate such
	// call sites across the module.
	out = append(out, s.ifaceCallArgs(d, idx)...)
	// Product boundary entries calling d directly supply the product's
	// own implementation — its results come from product-controlled data,
	// so the callback is an unknown-origin item, not a boundary constant.
	for _, e := range s.entries {
		if e.calleeKey != d.key || idx >= len(e.call.Args) {
			continue
		}
		s.addItem(domain.IngressItem{
			CallSite: e.site,
			Kind:     domain.IngressConeSource,
			Callee:   d.key,
			Origin:   domain.OriginUnknown,
			Detail:   "product supplies a func-valued argument — callback results come from product-controlled data",
		})
	}
	return out
}

// returnExprs finds a callee's declaration and returns its return-value
// expressions — used when a call produces a function value.
func (s *ingressScan) returnExprs(callerPkg *packages.Package, fn *types.Func) []rhsRef {
	var out []rhsRef
	push := func(pkg *packages.Package, decl *ast.FuncDecl) {
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			rs, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, e := range rs.Results {
				out = append(out, rhsRef{pkg, decl, e})
			}
			return true
		})
	}
	if d, ok := s.decls[s.calleeKey(fn)]; ok {
		push(d.pkg, d.decl)
		return out
	}
	if decl, dp := s.ix.funcDecl(fn); decl != nil {
		push(dp, decl)
	}
	return out
}

// selCall is one `x.M(arg)` call site inside module code — the method
// name, the statically declared receiver type and the argument at idx.
type selCall struct {
	rhsRef
	recv   types.Type
	obj    types.Object
	argIdx int
}

// ifaceCallArgs finds call sites `x.M(...)` inside module code where x's
// declared type is an interface that d's receiver implements — those
// callers may dispatch to d and supply argument idx.
func (s *ingressScan) ifaceCallArgs(d fnDeclRef, idx int) []rhsRef {
	if d.fn == nil {
		return nil
	}
	sig, ok := d.fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	drecv := sig.Recv().Type()
	if s.methodCalls == nil {
		s.methodCalls = map[string][]selCall{}
		for _, cd := range s.decls {
			if cd.pkg == nil || cd.pkg.TypesInfo == nil {
				continue
			}
			ast.Inspect(cd.decl.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				s2, ok := cd.pkg.TypesInfo.Selections[sel]
				if !ok {
					return true
				}
				for i, a := range ce.Args {
					s.methodCalls[sel.Sel.Name] = append(s.methodCalls[sel.Sel.Name],
						selCall{rhsRef{cd.pkg, cd.decl, a}, s2.Recv(), s2.Obj(), i})
				}
				return true
			})
		}
	}
	var out []rhsRef
	for _, c := range s.methodCalls[d.fn.Name()] {
		if c.argIdx != idx || c.obj == types.Object(d.fn) {
			continue // direct dispatch — covered by inEdges
		}
		iface, ok := c.recv.Underlying().(*types.Interface)
		if !ok {
			continue
		}
		if types.Implements(drecv, iface) {
			out = append(out, c.rhsRef)
			continue
		}
		if _, isPtr := drecv.(*types.Pointer); !isPtr && types.Implements(types.NewPointer(drecv), iface) {
			out = append(out, c.rhsRef)
		}
	}
	return out
}

// pkgOf returns the loaded package owning a package-level object.
func (s *ingressScan) pkgOf(v *types.Var) *packages.Package {
	if v.Pkg() == nil {
		return nil
	}
	for _, p := range s.modPkgs {
		if p.PkgPath == v.Pkg().Path() {
			return p
		}
	}
	for _, p := range s.ix.allExtras() {
		if p.PkgPath == v.Pkg().Path() {
			return p
		}
	}
	return nil
}

// inEdges lazily inverts the intra-module call graph.
func (s *ingressScan) inEdges() map[string][]string {
	if s.callers != nil {
		return s.callers
	}
	s.callers = map[string][]string{}
	for caller, callees := range s.edges {
		for callee := range callees {
			s.callers[callee] = append(s.callers[callee], caller)
		}
	}
	for _, l := range s.callers {
		sort.Strings(l)
	}
	return s.callers
}

// scanStdlibCall classifies a call to a non-module function by the
// knowledge base: modeled calls contribute known origins; unmodeled calls
// preserve UNKNOWN because they may return data or perform independent effects.
func (s *ingressScan) scanStdlibCall(pkg *packages.Package, d fnDeclRef, call *ast.CallExpr, fn *types.Func, push func(fnDeclRef)) {
	key := fn.Pkg().Path() + "." + fn.Name()
	if fn.Pkg().Path() == "reflect" && (fn.Name() == "TypeOf" || reflectTypeConstructor(fn)) {
		return
	}
	if callHasFunctionArg(pkg, call) {
		s.addUnknownCall(pkg, d, call, fn, "external callback may have independent effects")
		return
	}
	if formatArgsMayCallUserCode(pkg, call) {
		s.addUnknownCall(pkg, d, call, fn, "external call may invoke a formatting method with independent provenance")
		return
	}
	if fn.Pkg().Path() == "reflect" {
		if fn.Name() == "ValueOf" && len(call.Args) == 1 {
			o, why := s.ix.classify(pkg, d.decl, call.Args[0], 0)
			if !domain.SafeOrigin(o) {
				s.addItem(domain.IngressItem{
					CallSite: s.siteAt(pkg, d.decl, call.Pos()), Kind: domain.IngressConeSource,
					Callee: key, Origin: o, Detail: "reflect.ValueOf carries input provenance: " + why,
				})
			}
			return
		}
		if fn.Name() == "Call" || fn.Name() == "CallSlice" {
			pos := s.ix.fset.Position(call.Pos())
			s.blockers = append(s.blockers, fmt.Sprintf(
				"%s in %s at %s:%d — reflective invocation target is not proven closed",
				key, d.key, pos.Filename, pos.Line))
		}
		s.addUnknownCall(pkg, d, call, fn, "reflective value operation may carry or write non-constant data")
		return
	}
	if o, ok := s.ix.kb().SourceFuncs[key]; ok && o != domain.OriginConstant {
		s.addItem(domain.IngressItem{
			CallSite: s.siteAt(pkg, d.decl, call.Pos()),
			Kind:     domain.IngressConeSource,
			Callee:   key,
			Origin:   o,
			Detail:   "knowledge-base source",
		})
		return
	}
	if o, ok := s.ix.kb().SourceFuncs[key]; ok && o == domain.OriginConstant {
		return
	}
	if peerSourceCallee(fn) {
		s.addItem(domain.IngressItem{
			CallSite: s.siteAt(pkg, d.decl, call.Pos()),
			Kind:     domain.IngressConeSource,
			Callee:   key,
			Origin:   domain.OriginExternalUntrusted,
			Detail:   "peer channel primitive",
		})
		return
	}
	if s.ix.isDBFunc(fn) {
		s.addItem(domain.IngressItem{
			CallSite: s.siteAt(pkg, d.decl, call.Pos()),
			Kind:     domain.IngressConeSource,
			Callee:   key,
			Origin:   domain.OriginDatabase,
			Detail:   "database primitive",
		})
		return
	}
	if s.ix.isServiceCall(fn) {
		s.addItem(domain.IngressItem{
			CallSite: s.siteAt(pkg, d.decl, call.Pos()),
			Kind:     domain.IngressConeSource,
			Callee:   key,
			Origin:   domain.OriginInternalService,
			Detail:   "service stub call",
		})
		return
	}
	if o, w, ok := s.ix.httpClientOrigin(pkg, d.decl, fn, call, 0, s.ix.topEval(pkg, d.decl)); ok {
		s.addItem(domain.IngressItem{
			CallSite: s.siteAt(pkg, d.decl, call.Pos()),
			Kind:     domain.IngressConeSource,
			Callee:   key,
			Origin:   o,
			Detail:   "http client: " + w,
		})
		return
	}
	if idx, ok := s.ix.kb().PassthroughFuncs[key]; ok {
		if idx >= 0 && idx < len(call.Args) {
			o, why := s.ix.classify(pkg, d.decl, call.Args[idx], 0)
			s.addDerivedItem(pkg, d, call, fn, o, "passthrough result: "+why)
			return
		}
		s.addUnknownCall(pkg, d, call, fn, "invalid passthrough model argument")
		return
	}
	if s.ix.kb().ArgsMergeFuncs[key] {
		origin := domain.OriginConstant
		var why []string
		for _, arg := range call.Args {
			o, w := s.ix.classify(pkg, d.decl, arg, 0)
			origin = mergeOrigin(origin, o)
			why = append(why, w)
		}
		s.addDerivedItem(pkg, d, call, fn, origin, "merged arguments: "+strings.Join(why, " | "))
		return
	}
	if _, ok := s.ix.kb().PassthroughMethods[fn.Name()]; ok && sigHasReceiver(fn) {
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			o, why := s.ix.classify(pkg, d.decl, sel.X, 0)
			s.addDerivedItem(pkg, d, call, fn, o, "passthrough receiver: "+why)
			return
		}
		s.addUnknownCall(pkg, d, call, fn, "passthrough method receiver unresolved")
		return
	}
	if idxs, ok := s.ix.kb().SlicePopulateFuncs[key]; ok && idxs[1] >= 0 && idxs[1] < len(call.Args) {
		o, why := s.ix.classify(pkg, d.decl, call.Args[idxs[1]], 0)
		s.addDerivedItem(pkg, d, call, fn, o, "populated destination from: "+why)
		return
	}
	s.addUnknownCall(pkg, d, call, fn, "unmodeled external call may have independent effects")
}

func (s *ingressScan) addDerivedItem(pkg *packages.Package, d fnDeclRef, call *ast.CallExpr,
	fn *types.Func, origin domain.DataOrigin, detail string) {
	if domain.SafeOrigin(origin) {
		return
	}
	s.addItem(domain.IngressItem{
		CallSite: s.siteAt(pkg, d.decl, call.Pos()),
		Kind:     domain.IngressConeSource,
		Callee:   fn.Pkg().Path() + "." + fn.Name(),
		Origin:   origin,
		Detail:   detail,
	})
}

func reflectTypeConstructor(fn *types.Func) bool {
	switch fn.Name() {
	case "PtrTo", "PointerTo", "SliceOf", "ArrayOf", "MapOf", "ChanOf", "FuncOf", "StructOf":
		return true
	}
	return false
}

func sigHasReceiver(fn *types.Func) bool {
	sig, ok := fn.Type().(*types.Signature)
	return ok && sig.Recv() != nil
}

// reflectCall handles reflective invocation inside the cone.
// MethodByName/Method calls resolved to a literal name are bounded:
// methods of that name in every loaded package are queued for scanning.
// Unnamed reflective dispatch (Call on an arbitrary Value) blocks the
// closure — the invoked code may contain sources the inventory never saw.
func (s *ingressScan) reflectCall(pkg *packages.Package, d fnDeclRef, call *ast.CallExpr, fn *types.Func, push func(fnDeclRef)) {
	var names []string
	ast.Inspect(d.decl.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		f, ok := calleeObject(pkg.TypesInfo, c.Fun).(*types.Func)
		if !ok || f.Pkg() == nil || f.Pkg().Path() != "reflect" {
			return true
		}
		if f.Name() != "MethodByName" {
			return true
		}
		if len(c.Args) > 0 {
			if lit, ok := c.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
				names = append(names, strings.Trim(lit.Value, `"`))
			}
		}
		return true
	})
	pos := s.ix.fset.Position(call.Pos())
	if len(names) == 0 {
		s.blockers = append(s.blockers, fmt.Sprintf(
			"reflect.Value.%s in %s at %s:%d — invoked code not enumerable",
			fn.Name(), d.key, pos.Filename, pos.Line))
		return
	}
	// Bound the dispatch by method name across all loaded packages.
	for _, name := range names {
		for _, dp := range append(append([]*packages.Package{}, s.ix.allExtras()...), s.ix.pkgs...) {
			if dp.Types == nil {
				continue
			}
			for _, tn := range dp.Types.Scope().Names() {
				t := dp.Types.Scope().Lookup(tn).Type()
				ms := types.NewMethodSet(types.NewPointer(t))
				for i := 0; i < ms.Len(); i++ {
					m := ms.At(i).Obj()
					mf, ok := m.(*types.Func)
					if !ok || m.Name() != name {
						continue
					}
					if md, mp := s.ix.funcDecl(mf); md != nil && mp != nil {
						key := mp.PkgPath + "." + tn + "." + name
						push(fnDeclRef{pkg: mp, decl: md, key: key})
					}
				}
			}
		}
	}
	s.addItem(domain.IngressItem{
		CallSite: s.siteAt(pkg, d.decl, call.Pos()),
		Kind:     domain.IngressConeSource,
		Callee:   "reflect.Value." + fn.Name(),
		Origin:   domain.OriginGenerated,
		Detail:   fmt.Sprintf("reflective dispatch bounded to method-name enumeration (%s) over loaded packages", strings.Join(names, ",")),
	})
}

// ifaceOutOfModule flags interface call sites whose possible impls live
// outside the module (product callbacks or other dep modules). The impl
// scan is memoized per (iface, method): every dispatch site asks the
// same question, and types cannot be created at runtime to escape it.
func (s *ingressScan) ifaceOutOfModule(pkg *packages.Package, d fnDeclRef, call *ast.CallExpr, fn *types.Func) {
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return
	}
	if _, isIface := sig.Recv().Type().Underlying().(*types.Interface); !isIface {
		return
	}
	pos := s.ix.fset.Position(call.Pos())
	var ifaceTy *types.Interface
	iface := ifaceNamed(sig.Recv().Type())
	ikey := ""
	if iface != nil && iface.Obj() != nil {
		ifacePkg := "builtin"
		if iface.Obj().Pkg() != nil {
			ifacePkg = iface.Obj().Pkg().Path()
		}
		ikey = ifacePkg + "." + iface.Obj().Name() + "." + fn.Name()
	} else {
		// Anonymous interface — the method set still bounds impls;
		// enumerate them the same way, keyed by type structure.
		if it, ok := sig.Recv().Type().Underlying().(*types.Interface); ok {
			ikey = types.TypeString(sig.Recv().Type(), nil) + "." + fn.Name()
			ifaceTy = it
		}
	}
	if ikey == "" {
		s.blockers = append(s.blockers, fmt.Sprintf(
			"interface dispatch in %s at %s:%d — impls not enumerable",
			d.key, pos.Filename, pos.Line))
		return
	}
	method := fn.Name()
	outside, cached := s.ifaceCache[ikey]
	if !cached {
		if ifaceTy == nil {
			ifaceTy = iface.Underlying().(*types.Interface)
		}
		inst, narrowing := s.ix.instantiated()
		for _, dp := range append(append([]*packages.Package{}, s.ix.allExtras()...), s.ix.pkgs...) {
			if dp.Types == nil {
				continue
			}
			for _, tn := range dp.Types.Scope().Names() {
				nt, ok := dp.Types.Scope().Lookup(tn).(*types.TypeName)
				if !ok || nt.Pkg() == nil {
					continue
				}
				if _, isIface := nt.Type().Underlying().(*types.Interface); isIface {
					continue
				}
				implNamed, _ := nt.Type().(*types.Named)
				if narrowing && implNamed != nil && !inst[namedKey(implNamed)] {
					continue
				}
				if !types.Implements(types.NewPointer(nt.Type()), ifaceTy) {
					continue
				}
				ms := types.NewMethodSet(types.NewPointer(nt.Type()))
				has := false
				for i := 0; i < ms.Len(); i++ {
					if ms.At(i).Obj().Name() == method {
						has = true
					}
				}
				if !has {
					continue
				}
				// Implementations in the product or stdlib are
				// enumerable (bodies classify/trace on demand). Only an
				// impl owned by ANOTHER dependency module is opaque —
				// it could carry that module's autonomous sources in.
				implMod := s.pkgMod[nt.Pkg().Path()]
				if implMod != "" && implMod != s.module {
					outside = append(outside, nt.Pkg().Path()+"."+tn)
				}
			}
		}
		sort.Strings(outside)
		s.ifaceCache[ikey] = outside
	}
	if allowed := s.ix.dispatchImpls(pkg, d.decl, call); allowed != nil && outside != nil {
		var narrowed []string
		for _, qn := range outside {
			base := qn[strings.LastIndex(qn, ".")+1:]
			if allowed[base] {
				narrowed = append(narrowed, qn)
			}
		}
		outside = narrowed
	}
	if len(outside) > 0 {
		s.addItem(domain.IngressItem{
			CallSite: s.siteAt(pkg, d.decl, call.Pos()),
			Kind:     domain.IngressConeSource,
			Callee:   ikey,
			Origin:   domain.OriginUnknown,
			Detail:   fmt.Sprintf("interface dispatch may call implementations outside the module: %s — callback results unproven", strings.Join(outside, ", ")),
		})
	}
}

// checkPkgVar handles reads of a package-level var inside cone code by
// identifier; checkSelVar covers the pkg.Var selector form.
func (s *ingressScan) checkPkgVar(pkg *packages.Package, d fnDeclRef, id *ast.Ident) {
	obj := pkg.TypesInfo.ObjectOf(id)
	vr, ok := obj.(*types.Var)
	if !ok || vr.Pkg() == nil || vr.Parent() == nil || vr.Parent() != vr.Pkg().Scope() || vr.IsField() {
		return
	}
	s.varIngress(d, vr, id.Name, id.Pos())
}

func (s *ingressScan) checkSelVar(pkg *packages.Package, d fnDeclRef, sel *ast.SelectorExpr) {
	if _, isSel := pkg.TypesInfo.Selections[sel]; isSel {
		return // field/method selection, not a package var
	}
	vr, ok := pkg.TypesInfo.ObjectOf(sel.Sel).(*types.Var)
	if !ok || vr.Pkg() == nil {
		return
	}
	s.varIngress(d, vr, vr.Pkg().Path()+"."+vr.Name(), sel.Pos())
}

// varIngress inventories a package-level var read inside cone code. The
// var's origin is the merge of every enumerable write: declaration
// initializers, `v =`, `v.f =`, `v[k] =` assigns across the module and
// the product, and writes to the fields of its struct type (the mutable
// receiver state of shared objects). Escapes — &v, passing v to a call,
// storing or returning it — hand the writer set to code the scan cannot
// see, so the item becomes UNKNOWN. Vars outside the module (stdlib
// source vars, other dep modules) classify directly.
func (s *ingressScan) varIngress(d fnDeclRef, vr *types.Var, name string, pos token.Pos) {
	if !isPackageVar(vr) {
		return // local var or field — regular provenance tracing covers it
	}
	key := vr.Id()
	if s.varSeen[key] {
		return
	}
	s.varSeen[key] = true
	at := s.siteAt(d.pkg, d.decl, pos)
	mod := s.pkgMod[vr.Pkg().Path()]
	if mod != s.module {
		if mod == "" {
			// stdlib var — known external readers only.
			if vr.Pkg().Path() == "os" && (vr.Name() == "Args" || vr.Name() == "Stdin") {
				s.addItem(domain.IngressItem{
					CallSite: at,
					Kind:     domain.IngressConeSource,
					Callee:   name,
					Origin:   domain.OriginExternalUntrusted,
					Detail:   "os." + vr.Name(),
				})
			}
			return
		}
		s.addItem(domain.IngressItem{
			CallSite: at,
			Kind:     domain.IngressConeSource,
			Callee:   name,
			Origin:   domain.OriginUnknown,
			Detail:   fmt.Sprintf("package var of dependency module %s — its writers are outside the module scope", mod),
		})
		return
	}
	// Defer origin resolution until the whole cone is scanned — the
	// writer pass needs the complete set of read vars up front.
	s.varReads = append(s.varReads, varRead{vr: vr, name: name, site: at})
}

// varRead records a module package var read inside cone code — the
// writer pass enumerates its provenance once the cone is closed.
type varRead struct {
	vr   *types.Var
	name string
	site domain.CallSite
}

// emitVarItems resolves each inventoried module var's merged origin and
// records items for the ones that are not provably safe. Each var gets
// a fresh evaluation budget: the cone scan may have drained the shared
// budget, and an exhausted budget must not turn an unrelated, cheap
// initializer UNKNOWN by ordering.
func (s *ingressScan) emitVarItems() {
	for _, r := range s.varReads {
		s.ix.evalBudget = maxEvalBudget * 4
		origin, why, ok := s.pkgVarOrigin(r.vr)
		if !ok {
			s.addItem(domain.IngressItem{
				CallSite: r.site,
				Kind:     domain.IngressConeSource,
				Callee:   r.name,
				Origin:   domain.OriginUnknown,
				Detail:   "unclosed writer set: " + why,
			})
			continue
		}
		if origin != domain.OriginConstant && origin != domain.OriginGenerated {
			s.addItem(domain.IngressItem{
				CallSite: r.site,
				Kind:     domain.IngressConeSource,
				Callee:   r.name,
				Origin:   origin,
				Detail:   "mutable module state: " + why,
			})
		}
	}
}

// pkgVarOrigin merges every visible write to a module package var:
// initializers and assignments, element/field writes through the var's
// own name or local aliases (`m := v; m[k] = x`), writes to fields
// holding the var (`x.f = v; x.f[k] = y`), arguments handed to in-module
// callees via `f(v)` (the callee may write through its parameter), and
// writes to fields of the var's declared struct type. Returns ok=false
// when the writer set cannot be closed (untracked escapes, foreign
// mutators).
//
// Writer enumeration runs once per inventory over every package var —
// a single pass per declaration maps all bare-var events at once instead
// of re-walking every function body for each var.
func (s *ingressScan) pkgVarOrigin(vr *types.Var) (domain.DataOrigin, string, bool) {
	if s.varWrites == nil {
		s.varWrites = s.collectVarWrites()
	}
	var merged domain.DataOrigin
	var whys []string
	complete := true
	merge := func(o domain.DataOrigin, w string) {
		merged = mergeOrigin(merged, o)
		whys = append(whys, w)
	}
	incomplete := func(w string) {
		complete = false
		merge(domain.OriginUnknown, w)
	}

	ws := s.varWrites[vr]
	for _, r := range ws.writes {
		o, w := s.ix.classify(r.pkg, r.enc, r.expr, 1)
		merge(o, "write "+w)
	}
	for _, r := range ws.methArgs {
		o, w := s.ix.classify(r.pkg, r.enc, r.expr, 1)
		merge(o, "mutating foreign method arg "+w)
	}
	for _, pw := range ws.paramCallees {
		if !s.scanCalleeParamWrites(pw.pkg, pw.fn, pw.argIdx, merge) {
			incomplete("shared var passed to unresolvable/foreign callee")
		}
	}
	for _, w := range ws.escapes {
		incomplete(w)
	}

	// Writes to the fields of the var's declared type — the receiver
	// state of the shared object (registry maps, cached tables). Only
	// types declared in the module have enumerable writers; foreign types
	// are covered by the call-argument handling above.
	nt := recvNamed(vr.Type())
	if nt != nil && nt.Obj() != nil && nt.Obj().Pkg() != nil && s.inModule(nt.Obj().Pkg().Path()) {
		if st, ok := nt.Underlying().(*types.Struct); ok {
			for i := 0; i < st.NumFields(); i++ {
				fv := st.Field(i)
				for _, w := range s.ix.fieldWriteSites(fv) {
					o, why := s.ix.classify(w.pkg, w.enc, w.rhs, 1)
					merge(o, fmt.Sprintf("field %s write: %s", fv.Name(), why))
				}
			}
		}
	}

	if merged == "" {
		return domain.OriginConstant, "zero value, no writes", true
	}
	return merged, strings.Join(whys, "; "), complete
}

// varWriteSet accumulates everything a single declaration pass observed
// about one package var: values written into it and the escapes that
// leave its writer set unclosed.
type varWriteSet struct {
	writes       []rhsAt
	methArgs     []rhsAt
	paramCallees []paramWrite
	escapes      []string
	inited       bool // declaration initializer seen
}

type rhsAt struct {
	pkg  *packages.Package
	enc  *ast.FuncDecl
	expr ast.Expr
}

type paramWrite struct {
	pkg    *packages.Package
	fn     *types.Func
	argIdx int
}

// collectVarWrites walks module and product source once and records all
// writes/escapes of package-level vars read anywhere in the cone. Local
// aliases (`x := v`) and field aliases (`x.f = v`) for reference-typed
// vars are tracked so writes through them are enumerated rather than
// treated as unbounded escapes; statements are visited in source order,
// matching Go's lexical scoping (an alias can't be used before bound).
func (s *ingressScan) collectVarWrites() map[*types.Var]*varWriteSet {
	sets := map[*types.Var]*varWriteSet{}
	// Keyed by types.Id — the read-side object and the write-side
	// object come from different packages.Load calls, so pointers and
	// object equality both fail across loads.
	want := map[string]*types.Var{}
	for _, r := range s.varReads {
		want[r.vr.Id()] = r.vr
		sets[r.vr] = &varWriteSet{}
	}
	get := func(v *types.Var) *types.Var {
		if v == nil || !isPackageVar(v) {
			return nil
		}
		vr := want[v.Id()]
		if vr == nil {
			return nil
		}
		if sets[vr] == nil {
			sets[vr] = &varWriteSet{}
		}
		return vr
	}
	scope := append(append([]*packages.Package{}, s.modPkgs...), s.ix.pkgs...)
	for _, pkg := range scope {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			for _, decl := range f.Decls {
				switch decl := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range decl.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for i, nm := range vs.Names {
							v, _ := info.ObjectOf(nm).(*types.Var)
							vr := get(v)
							if vr != nil && i < len(vs.Values) {
								sets[vr].inited = true
								sets[vr].writes = append(sets[vr].writes,
									rhsAt{pkg, nil, vs.Values[i]})
							}
						}
					}
				case *ast.FuncDecl:
					s.scanDeclVarEvents(pkg, decl, get, sets)
				}
			}
		}
	}
	return sets
}

// scanDeclVarEvents records var writes/escapes inside one function body.
// get resolves a bare-identifier object to a wanted package var (nil when
// the identifier isn't an inventoried var).
func (s *ingressScan) scanDeclVarEvents(pkg *packages.Package, enc *ast.FuncDecl,
	get func(*types.Var) *types.Var, sets map[*types.Var]*varWriteSet) {
	if enc == nil || enc.Body == nil {
		return
	}
	info := pkg.TypesInfo
	// local ident/field → the package var it currently aliases.
	aliases := map[types.Object]*types.Var{}
	fields := map[types.Object]*types.Var{}
	resolve := func(v *types.Var) *types.Var {
		if v == nil {
			return nil
		}
		if vr := aliases[types.Object(v)]; vr != nil {
			return vr
		}
		return get(v)
	}
	bind := func(lhs ast.Expr, rhs ast.Expr) {
		vr := resolve(bareVarObj(info, rhs))
		if vr == nil || !varShareable(vr) {
			return
		}
		if id, ok := lhs.(*ast.Ident); ok {
			if obj := info.ObjectOf(id); obj != nil && obj != vr {
				aliases[obj] = vr
			}
			return
		}
		if sel, ok := lhs.(*ast.SelectorExpr); ok {
			if sl, ok2 := info.Selections[sel]; ok2 {
				fields[sl.Obj()] = vr
			}
		}
	}

	ast.Inspect(enc.Body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.AssignStmt:
			// Alias binding first: `x := v` / `x.f = v` must register
			// before writes through the alias later in the body.
			if len(node.Lhs) == len(node.Rhs) {
				for i := range node.Lhs {
					bind(node.Lhs[i], node.Rhs[i])
				}
			}
			for i, lhs := range node.Lhs {
				// Rebinding an alias (`x.f = other`) is not a write.
				if sel, ok := lhs.(*ast.SelectorExpr); ok {
					if sl, ok2 := info.Selections[sel]; ok2 && fields[sl.Obj()] != nil {
						continue
					}
				}
				var vr *types.Var
				if b := lhsBaseIdent(info, lhs); b != nil {
					if bv, ok := info.ObjectOf(b).(*types.Var); ok {
						vr = resolve(bv)
					}
				}
				if vr == nil && len(fields) > 0 {
					vr = lhsFieldVar(info, lhs, fields)
				}
				if vr == nil {
					continue
				}
				var rhs ast.Expr
				if i < len(node.Rhs) {
					rhs = node.Rhs[i]
				} else if len(node.Rhs) == 1 {
					rhs = node.Rhs[0]
				}
				if rhs == nil || resolve(bareVarObj(info, rhs)) == vr {
					continue // alias rebinding, not a write of new data
				}
				sets[vr].writes = append(sets[vr].writes, rhsAt{pkg, enc, rhs})
			}
		case *ast.ValueSpec:
			// `var x = v` inside a function — a local alias too.
			for i, nm := range node.Names {
				if i < len(node.Values) {
					bind(nm, node.Values[i])
				}
			}
		case *ast.ReturnStmt:
			for _, r := range node.Results {
				if vr := resolve(bareVarObj(info, r)); vr != nil && varShareable(vr) {
					sets[vr].escapes = append(sets[vr].escapes,
						"shared var returned — writers through the alias invisible")
				}
			}
		case *ast.SendStmt:
			if vr := resolve(bareVarObj(info, node.Value)); vr != nil && varShareable(vr) {
				sets[vr].escapes = append(sets[vr].escapes, "shared var sent on channel")
			}
		case *ast.CompositeLit:
			for _, e := range node.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok {
					e = kv.Value
				}
				if vr := resolve(bareVarObj(info, e)); vr != nil && varShareable(vr) {
					sets[vr].escapes = append(sets[vr].escapes, "shared var stored in a container")
				}
			}
		case *ast.CallExpr:
			if isLenCap(info, node) {
				break
			}
			for ai, a := range node.Args {
				vr := resolve(bareVarObj(info, a))
				if vr == nil {
					continue
				}
				if tv, ok := info.Types[node.Fun]; ok && tv.IsType() {
					continue // conversion — no call, no hidden writes
				}
				if !varShareable(vr) {
					continue // by-value handoff — the callee mutates a copy
				}
				fn, _ := calleeObject(info, node.Fun).(*types.Func)
				if fn != nil && fn.Pkg() != nil && s.inModule(fn.Pkg().Path()) {
					sets[vr].paramCallees = append(sets[vr].paramCallees,
						paramWrite{pkg, fn, ai})
					continue
				}
				sets[vr].escapes = append(sets[vr].escapes,
					"shared var passed to unresolvable/foreign callee")
			}
			// `v.M(args)` — mutating foreign methods can write args
			// into v's state invisibly; read-only methods do not change
			// v's provenance.
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok {
				if b := lhsBaseIdent(info, sel.X); b != nil {
					var vr *types.Var
					if bv, ok2 := info.ObjectOf(b).(*types.Var); ok2 {
						vr = resolve(bv)
					}
					if vr != nil {
						if fn, ok2 := calleeObject(info, node.Fun).(*types.Func); ok2 {
							if fn.Pkg() == nil || !s.inModule(fn.Pkg().Path()) {
								switch {
								case s.ix.kb().RecvMutateMethods[fn.Name()] || s.ix.kb().PopulateNames[fn.Name()]:
									for _, a := range node.Args {
										sets[vr].methArgs = append(sets[vr].methArgs, rhsAt{pkg, enc, a})
									}
								case fn.Pkg() != nil && s.pkgMod[fn.Pkg().Path()] != "":
									sets[vr].escapes = append(sets[vr].escapes,
										"var receiver handed to unlisted method of another dependency module")
								}
							}
						}
					}
				}
			}
		case *ast.UnaryExpr:
			if node.Op == token.AND {
				if vr := resolve(bareVarObj(info, node.X)); vr != nil {
					sets[vr].escapes = append(sets[vr].escapes, "address of var taken")
				}
			}
		}
		return true
	})
}

// isPackageVar reports whether v is a package-level variable — its
// parent scope is the package scope. Local vars and struct fields share
// the same types.Id as a same-named package var, so Id-keyed lookups
// must filter them out explicitly.
func isPackageVar(v *types.Var) bool {
	if v == nil || v.Pkg() == nil || v.IsField() {
		return false
	}
	return v.Parent() != nil && v.Parent() == v.Pkg().Scope()
}

// bareVarObj returns the var a bare expression refers to — `v`, `(v)`.
func bareVarObj(info *types.Info, e ast.Expr) *types.Var {
	switch v := e.(type) {
	case *ast.Ident:
		if vr, ok := info.ObjectOf(v).(*types.Var); ok {
			return vr
		}
	case *ast.ParenExpr:
		return bareVarObj(info, v.X)
	}
	return nil
}

// lhsFieldVar returns the package var whose field alias appears inside
// the LHS — `x.f[i] =` or `x.f.g =` writes where f is bound to the var.
func lhsFieldVar(info *types.Info, lhs ast.Expr, fields map[types.Object]*types.Var) *types.Var {
	var out *types.Var
	ast.Inspect(lhs, func(n ast.Node) bool {
		if out != nil {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sl, ok := info.Selections[sel]; ok && fields[sl.Obj()] != nil {
			out = fields[sl.Obj()]
		}
		return out == nil
	})
	return out
}

func varShareable(vr *types.Var) bool {
	switch vr.Type().Underlying().(type) {
	case *types.Map, *types.Slice, *types.Chan, *types.Pointer, *types.Signature:
		return true
	}
	return false
}

// lhsAliasesField reports whether the LHS expression writes through a
// field alias — `x.f[i] =`, `x.f.g =` where f is bound to the var.
func lhsAliasesField(info *types.Info, lhs ast.Expr, fields map[types.Object]bool) bool {
	found := false
	ast.Inspect(lhs, func(n ast.Node) bool {
		if found {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		if sl, ok := info.Selections[sel]; ok && fields[sl.Obj()] {
			found = true
		}
		return !found
	})
	return found
}

// isBareAlias reports whether e is a bare reference to an alias var.
func isBareAlias(info *types.Info, e ast.Expr, aliases map[types.Object]bool) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return aliases[info.ObjectOf(v)]
	case *ast.ParenExpr:
		return isBareAlias(info, v.X, aliases)
	}
	return false
}

// scanCalleeParamWrites merges the writes an in-module callee performs
// through parameter ai — the callee body may assign `p[k] =`/`p.f =`,
// reaching the caller's shared var. Returns false when the callee body
// is unavailable (foreign/stdlib) — the call then counts as an escape.
func (s *ingressScan) scanCalleeParamWrites(pkg *packages.Package, fn *types.Func, argIdx int, merge func(domain.DataOrigin, string)) bool {
	if fn == nil || fn.Pkg() == nil || !s.inModule(fn.Pkg().Path()) {
		return false
	}
	fd, fp := s.ix.funcDecl(fn)
	if fd == nil || fp == nil || fd.Type == nil || fd.Type.Params == nil {
		return false
	}
	// Map arg index to the param object.
	idx := argIdx
	for _, field := range fd.Type.Params.List {
		for _, name := range field.Names {
			if idx == 0 {
				p := fp.TypesInfo.ObjectOf(name)
				if p == nil {
					return false
				}
				found := false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					as, ok := n.(*ast.AssignStmt)
					if !ok {
						return true
					}
					for i, lhs := range as.Lhs {
						if b := lhsBaseIdent(fp.TypesInfo, lhs); b != nil && sameObject(fp.TypesInfo.ObjectOf(b), p) {
							var rhs ast.Expr
							if i < len(as.Rhs) {
								rhs = as.Rhs[i]
							} else if len(as.Rhs) == 1 {
								rhs = as.Rhs[0]
							}
							if rhs != nil {
								o, w := s.ix.classify(fp, fd, rhs, 1)
								merge(o, "callee write "+w)
							}
							found = true
						}
					}
					return true
				})
				_ = found
				return true
			}
			idx--
		}
	}
	return false
}

// modScope returns loaded packages of the analyzed module.
func (s *ingressScan) modScope() []*packages.Package {
	return s.modPkgs
}

// funText renders a call target for diagnostics.
func funText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return funText(v.X) + "." + v.Sel.Name
	case *ast.IndexExpr:
		return funText(v.X) + "[...]"
	case *ast.IndexListExpr:
		return funText(v.X) + "[...]"
	case *ast.StarExpr:
		return "*" + funText(v.X)
	}
	return fmt.Sprintf("%T", e)
}

// isBareVar reports whether e is exactly a reference to obj — `v` or
// `(v)` — not a field, element or call result built from it. Only a
// bare binding shares the var's storage; `v[k]`/`v.f` pass a copy of
// an element/field.
func isBareVar(info *types.Info, e ast.Expr, obj types.Object) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return sameObject(info.ObjectOf(v), obj)
	case *ast.ParenExpr:
		return isBareVar(info, v.X, obj)
	}
	return false
}

func isLenCap(info *types.Info, call *ast.CallExpr) bool {
	if b, ok := calleeObject(info, call.Fun).(*types.Builtin); ok {
		return b.Name() == "len" || b.Name() == "cap"
	}
	return false
}

// siteAt builds a CallSite inside a scanned declaration.
func (s *ingressScan) siteAt(pkg *packages.Package, enc *ast.FuncDecl, pos token.Pos) domain.CallSite {
	p := s.ix.fset.Position(pos)
	cs := domain.CallSite{File: p.Filename, Line: p.Line, Column: p.Column, Package: pkg.PkgPath}
	if enc != nil && enc.Name != nil {
		cs.Function = enc.Name.Name
		if enc.Recv != nil && len(enc.Recv.List) > 0 {
			cs.Receiver = recvDeclName(enc.Recv.List[0].Type)
		}
	}
	return cs
}

// addItem appends an inventory item.
func (s *ingressScan) addItem(it domain.IngressItem) {
	s.items = append(s.items, it)
}

// importedByProduct returns package paths transitively imported by the
// product — the set of module packages whose init() bodies actually run
// in the product binary.
func (s *ingressScan) importedByProduct() map[string]bool {
	reach := map[string]bool{}
	var work []*types.Package
	for _, p := range s.ix.pkgs {
		if p.Types != nil {
			work = append(work, p.Types)
		}
	}
	for len(work) > 0 {
		p := work[len(work)-1]
		work = work[:len(work)-1]
		if reach[p.Path()] {
			continue
		}
		reach[p.Path()] = true
		for _, im := range p.Imports() {
			if im != nil && !reach[im.Path()] {
				work = append(work, im)
			}
		}
	}
	return reach
}

// annotateReaches fills Reaches for cone items not covered by
// markReaches: a cone-source item is linked to a condition subject when
// its enclosing function and the subject are connected through the call
// graph in either direction — the source's data can flow into callees
// below it or be stored for ancestors above it. An item with no
// connection to any subject is not payload-relevant.
func (s *ingressScan) annotateReaches() {
	for i := range s.items {
		it := &s.items[i]
		if len(it.Reaches) > 0 || it.CallSite.Function == "" || it.CallSite.Package == "" {
			continue
		}
		owner := it.CallSite.Package + "."
		if it.CallSite.Receiver != "" {
			owner += it.CallSite.Receiver + "."
		}
		owner += it.CallSite.Function
		var r []string
		for subj := range s.subjects {
			if owner == subj || bfsChain(s.edges, owner, subj) != nil || bfsChain(s.edges, subj, owner) != nil {
				r = append(r, subj)
			}
		}
		sort.Strings(r)
		it.Reaches = r
	}
}
