package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// CheckMissingCall verifies whether a security check method (e.g. MapClaims.VerifyAudience)
// is omitted across the active execution path of a reached pipeline (e.g. MapClaims.Valid).
//
// Returns:
//   - omitted = true if pipeline is reached from product code and check has 0 invocations
//     on that execution path.
//   - omitted = false if pipeline is unreached, or if check is invoked in product callers,
//     intermediate dependency callers, the pipeline body, or transitive callees.
func (ix *Index) CheckMissingCall(ctx context.Context, check, pipeline domain.SymbolRef) (bool, string, error) {
	if ix == nil {
		return false, "", nil
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()

	if err := ix.load(ctx); err != nil {
		return false, "", err
	}
	if _, err := ix.loadExtra(ctx, pipeline.Package); err != nil {
		return false, "", err
	}
	if check.Package != pipeline.Package && check.Package != "" {
		if _, err := ix.loadExtra(ctx, check.Package); err != nil {
			return false, "", err
		}
	}

	subjPkgs := ix.extrasFor(pipeline.Package)
	mod := ""
	for _, p := range subjPkgs {
		if p.Module != nil {
			mod = p.Module.Path
			break
		}
	}
	pkgs := subjPkgs
	if mod != "" {
		pkgs = ix.modulePkgs(mod)
	}

	// 1. Verify pipeline is reached from product code.
	reached, pathStr, prodCallers, intermediateFns := ix.findPipelineReach(ctx, pipeline, pkgs, mod)
	if !reached {
		return false, fmt.Sprintf("pipeline %s is not reached from product code", pipeline.Symbol), nil
	}

	// 2. Collect interface refs for check to catch interface dispatches.
	checkIfaceRefs := ix.ifaceCallerRefs(check)

	// 3. Search for invocations of check in product code.
	prodCheckCalls := ix.productRefsTo(check)
	for _, iref := range checkIfaceRefs {
		prodCheckCalls = append(prodCheckCalls, ix.productRefsTo(iref)...)
	}
	if len(prodCheckCalls) > 0 {
		site := prodCheckCalls[0]
		return false, fmt.Sprintf("security check %s is invoked in product code at %s:%d (%s.%s)",
			check.Symbol, filepathBase(site.File), site.Line, site.Package, site.Function), nil
	}

	// 4. Search for invocations of check in intermediate dependency callers.
	for _, item := range intermediateFns {
		if site := callsSymbol(item.pkg, item.fn, check, checkIfaceRefs); site != nil {
			return false, fmt.Sprintf("security check %s is invoked in dependency caller at %s:%d (%s.%s)",
				check.Symbol, filepathBase(site.File), site.Line, site.Package, site.Function), nil
		}
	}

	// 5. Search for invocations of check in pipeline body and its dep-internal callees.
	pipelinePkg, pipelineFn := findFuncDecl(pkgs, pipeline)
	if pipelineFn == nil {
		return false, fmt.Sprintf("cannot inspect pipeline: declaration %s not found in analyzed packages", pipeline.Symbol), nil
	}
	if site := callsSymbol(pipelinePkg, pipelineFn, check, checkIfaceRefs); site != nil {
		return false, fmt.Sprintf("security check %s is invoked in pipeline body at %s:%d (%s.%s)",
			check.Symbol, filepathBase(site.File), site.Line, site.Package, site.Function), nil
	}

	// Transitive callees of pipeline within the dependency module.
	site, truncated := ix.searchCalleesForCheck(pkgs, pipelinePkg, pipelineFn, check, checkIfaceRefs, mod)
	if site != nil {
		return false, fmt.Sprintf("security check %s is invoked in pipeline callee at %s:%d (%s.%s)",
			check.Symbol, filepathBase(site.File), site.Line, site.Package, site.Function), nil
	}
	if truncated {
		return false, fmt.Sprintf("cannot verify omission: callee search for %s exceeded search depth limit", pipeline.Symbol), nil
	}

	// 6. Pipeline reached and check has 0 invocations on this active path.
	typeName, _ := splitSymbol(check.Symbol)
	content := fmt.Sprintf(
		"security check %s is omitted on active pipeline %s (receiver: %s.%s; product callers: %d); path: %s; check invocations on path: 0",
		check.Symbol, pipeline.Symbol, check.Package, typeName, len(prodCallers), pathStr,
	)
	return true, content, nil
}

type funcDeclItem struct {
	pkg *packages.Package
	fn  *ast.FuncDecl
}

// findPipelineReach determines whether pipeline is reached from product code.
func (ix *Index) findPipelineReach(ctx context.Context, pipeline domain.SymbolRef, pkgs []*packages.Package, mod string) (bool, string, []domain.CallSite, []funcDeclItem) {
	// A. Direct product call sites to pipeline.
	directProdCalls := ix.productRefsTo(pipeline)
	for _, iref := range ix.ifaceCallerRefs(pipeline) {
		directProdCalls = append(directProdCalls, ix.productRefsTo(iref)...)
	}
	if len(directProdCalls) > 0 {
		site := directProdCalls[0]
		pathStr := fmt.Sprintf("%s.%s (%s:%d) -> %s", site.Package, site.Function, filepathBase(site.File), site.Line, pipeline.Symbol)
		return true, pathStr, directProdCalls, nil
	}

	// B. Call sites of pipeline (or interface methods it implements) in dependency packages.
	targetSites := ix.findCallSitesIn(pkgs, pipeline)
	for _, iref := range ix.ifaceCallerRefs(pipeline) {
		targetSites = append(targetSites, ix.findCallSitesIn(pkgs, iref)...)
	}

	type queueItem struct {
		ref       domain.SymbolRef
		chainFns  []funcDeclItem
		chainDesc string
	}

	var queue []queueItem
	visited := map[string]bool{}

	for _, s := range targetSites {
		if s.enclosing == nil || s.enclosing.Name == nil || s.pkg == nil {
			continue
		}
		symName := s.enclosing.Name.Name
		if s.enclosing.Recv != nil && len(s.enclosing.Recv.List) > 0 {
			symName = recvDeclName(s.enclosing.Recv.List[0].Type) + "." + symName
		}
		ref := domain.SymbolRef{Package: s.pkg.PkgPath, Symbol: symName}
		key := ref.Package + "." + ref.Symbol
		if visited[key] {
			continue
		}
		visited[key] = true
		desc := ref.Symbol + " -> " + pipeline.Symbol
		item := funcDeclItem{pkg: s.pkg, fn: s.enclosing}
		queue = append(queue, queueItem{ref: ref, chainFns: []funcDeclItem{item}, chainDesc: desc})
	}

	// Upward BFS to find product caller.
	steps := 0
	for len(queue) > 0 && steps < 100 {
		steps++
		curr := queue[0]
		queue = queue[1:]

		pCalls := ix.productRefsTo(curr.ref)
		if len(pCalls) > 0 {
			site := pCalls[0]
			pathStr := fmt.Sprintf("%s.%s (%s:%d) -> %s", site.Package, site.Function, filepathBase(site.File), site.Line, curr.chainDesc)
			return true, pathStr, pCalls, curr.chainFns
		}

		// Find callers of curr.ref in dependency packages.
		depCallers := ix.findCallSitesIn(pkgs, curr.ref)
		for _, iref := range ix.ifaceCallerRefs(curr.ref) {
			depCallers = append(depCallers, ix.findCallSitesIn(pkgs, iref)...)
		}

		for _, cs := range depCallers {
			if cs.enclosing == nil || cs.enclosing.Name == nil || cs.pkg == nil {
				continue
			}
			sName := cs.enclosing.Name.Name
			if cs.enclosing.Recv != nil && len(cs.enclosing.Recv.List) > 0 {
				sName = recvDeclName(cs.enclosing.Recv.List[0].Type) + "." + sName
			}
			nextRef := domain.SymbolRef{Package: cs.pkg.PkgPath, Symbol: sName}
			k := nextRef.Package + "." + nextRef.Symbol
			if visited[k] {
				continue
			}
			visited[k] = true
			nextChain := append([]funcDeclItem{{pkg: cs.pkg, fn: cs.enclosing}}, curr.chainFns...)
			nextDesc := nextRef.Symbol + " -> " + curr.chainDesc
			queue = append(queue, queueItem{ref: nextRef, chainFns: nextChain, chainDesc: nextDesc})
		}
	}

	return false, "", nil, nil
}

// searchCalleesForCheck performs a BFS over callees reachable from startFn within the dep module.
// Returns (foundSite, truncated).
func (ix *Index) searchCalleesForCheck(pkgs []*packages.Package, startPkg *packages.Package, startFn *ast.FuncDecl, check domain.SymbolRef, ifaces []domain.SymbolRef, mod string) (*domain.CallSite, bool) {
	visited := map[string]bool{}
	startKey := startPkg.PkgPath + "." + funcDeclSymbol(startFn)
	visited[startKey] = true

	queue := []funcDeclItem{{pkg: startPkg, fn: startFn}}
	steps := 0

	for len(queue) > 0 && steps < 100 {
		steps++
		curr := queue[0]
		queue = queue[1:]

		if curr.fn.Body == nil || curr.pkg.TypesInfo == nil {
			continue
		}

		callees := findCalleesInFunc(pkgs, curr.pkg, curr.fn, mod)
		for _, callee := range callees {
			k := callee.pkg.PkgPath + "." + funcDeclSymbol(callee.fn)
			if visited[k] {
				continue
			}
			visited[k] = true

			// Check if this callee calls check.
			if site := callsSymbol(callee.pkg, callee.fn, check, ifaces); site != nil {
				return site, false
			}
			queue = append(queue, callee)
		}
	}
	if len(queue) > 0 {
		return nil, true
	}
	return nil, false
}

// findCalleesInFunc finds all function declarations within the module called by fn.
func findCalleesInFunc(pkgs []*packages.Package, pkg *packages.Package, fn *ast.FuncDecl, mod string) []funcDeclItem {
	var out []funcDeclItem
	seen := map[string]bool{}

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		obj := calleeObject(pkg.TypesInfo, call.Fun)
		fnObj, ok := obj.(*types.Func)
		if !ok || fnObj.Pkg() == nil {
			return true
		}
		pPath := fnObj.Pkg().Path()
		if mod != "" && pPath != mod && !strings.HasPrefix(pPath, mod+"/") {
			return true
		}

		sym := fnObj.Name()
		if sig, ok := fnObj.Type().(*types.Signature); ok && sig.Recv() != nil {
			sym = recvTypeName(sig.Recv().Type()) + "." + sym
		}
		key := pPath + "." + sym
		if seen[key] {
			return true
		}
		seen[key] = true

		if calleePkg, calleeFn := findFuncDecl(pkgs, domain.SymbolRef{Package: pPath, Symbol: sym}); calleeFn != nil {
			out = append(out, funcDeclItem{pkg: calleePkg, fn: calleeFn})
		}
		return true
	})
	return out
}

func funcDeclSymbol(fn *ast.FuncDecl) string {
	if fn == nil || fn.Name == nil {
		return ""
	}
	name := fn.Name.Name
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		name = recvDeclName(fn.Recv.List[0].Type) + "." + name
	}
	return name
}

// findFuncDecl locates the ast.FuncDecl for a symbol reference in pkgs.
func findFuncDecl(pkgs []*packages.Package, ref domain.SymbolRef) (*packages.Package, *ast.FuncDecl) {
	typeName, name := splitSymbol(ref.Symbol)
	for _, p := range pkgs {
		if p.PkgPath != ref.Package {
			continue
		}
		for _, f := range p.Syntax {
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name == nil || fn.Name.Name != name {
					continue
				}
				if typeName == "" {
					if fn.Recv == nil || len(fn.Recv.List) == 0 {
						return p, fn
					}
					continue
				}
				if fn.Recv != nil && len(fn.Recv.List) > 0 {
					if recvDeclName(fn.Recv.List[0].Type) == typeName {
						return p, fn
					}
				}
			}
		}
	}
	return nil, nil
}

// callsSymbol checks whether fn's body contains any call to target or any of its interface methods.
func callsSymbol(pkg *packages.Package, fn *ast.FuncDecl, target domain.SymbolRef, ifaces []domain.SymbolRef) *domain.CallSite {
	if pkg == nil || fn == nil || fn.Body == nil || pkg.TypesInfo == nil {
		return nil
	}
	var found *domain.CallSite
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if found != nil {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		match := callIsSymbol(pkg.TypesInfo, call.Fun, target)
		if !match {
			for _, iface := range ifaces {
				if callIsSymbol(pkg.TypesInfo, call.Fun, iface) {
					match = true
					break
				}
			}
		}
		if match {
			pos := pkg.Fset.Position(call.Pos())
			callerName := fn.Name.Name
			if fn.Recv != nil && len(fn.Recv.List) > 0 {
				callerName = recvDeclName(fn.Recv.List[0].Type) + "." + callerName
			}
			found = &domain.CallSite{
				Package:  pkg.PkgPath,
				Function: callerName,
				File:     pos.Filename,
				Line:     pos.Line,
			}
			return false
		}
		return true
	})
	return found
}
