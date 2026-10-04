package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/build"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/tools/go/packages"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Index is a lazily loaded go/packages view of the analyzed product.
// It backs the targeted source tools (find_symbol, find_callers,
// read_function, find_entrypoints, argument provenance).
type Index struct {
	Dir   string
	Build domain.ProductSnapshot
	// Env carries the target toolchain (PATH/GOTOOLCHAIN) into package
	// loading, so stdlib symbols resolve under the release's GOROOT, not
	// the local toolchain's.
	Env []string
	// KB is the ecosystem-semantics knowledge base provenance and
	// exposure scans consult; nil installs DefaultKnowledge() on first
	// use. Set it before the first query — reconfiguring mid-analysis is
	// not supported.
	KB *Knowledge
	// hopLimit overrides the default caller-climb bound during a single
	// TraceArgumentBound call; 0 = maxTraceHops.
	hopLimit int
	// txBuf, when non-nil during TraceArgument, accumulates the calls a
	// traced value passes through (DataFlow.Transformations). txSeen
	// dedups it — a dep-cone trace otherwise appends one entry per
	// evaluated call (millions of entries on aws-scale cones).
	// Guarded by mu.
	txBuf  *[]domain.CallSite
	txSeen map[domain.CallSite]bool
	// traceSeen, when non-nil during TraceArgument, marks local vars whose
	// assignment merge is in progress — breaks self-referential cycles
	// (x = x + n re-entering x's assignments).
	traceSeen map[types.Object]bool
	// calleeEvalSeen marks vars whose assignment merge is in progress
	// inside evalCalleeExpr — the callee-frame counterpart of traceSeen,
	// owned by the callee evaluator so the cycle guard holds on every
	// entry path.
	calleeEvalSeen map[types.Object]bool
	// calleeTraceIn marks functions whose body trace is in progress —
	// breaks recursive callee chains (f → … → f) that would otherwise
	// re-scan the whole body exponentially until the eval budget dies.
	calleeTraceIn map[string]bool
	// paramSeen marks (function, argument-slot) resolutions in progress
	// inside traceParam/traceReceiver — recursive self-calls that re-feed
	// the same slot contribute no new origin and are cut here instead of
	// unrolling to the hop bound.
	paramSeen map[string]bool
	// paramCache memoizes completed (function, argument-slot) resolutions:
	// sibling branches of a caller merge would otherwise re-descend the
	// same caller chain at ever-greater depth and hit the hop bound.
	paramCache map[string]classifyResult
	// linkedSet/linkedGen cache the program's import closure (product
	// roots + transitively imported packages) for callerReachable's
	// dead-package exclusion — invalidated like callerCache on extras.
	linkedSet map[string]bool
	linkedGen int
	// activeCtx is the context of the currently executing public query —
	// internal helpers (loadExtra, findSymbol, dep-package loads) pick it
	// up so cancellation reaches subprocess loads without threading ctx
	// through every helper signature. Set by load() on every entry.
	activeCtx context.Context
	// classifyCache memoizes classify results for the duration of one
	// trace (reset at each trace entry — traceSeen/txBuf make results
	// trace-scoped). Without it the caller fan-out re-walks the same
	// (expr, enc, depth) subtrees exponentially.
	classifyCache map[classifyKey]classifyResult
	// assignCache memoizes localAssigns scans per (function, object);
	// callListCache memoizes the call-list walk in populatedByCall per
	// function. Both hold AST pointers — bounded like the other caches.
	assignCache   map[assignKey][]ast.Expr
	callListCache map[*ast.FuncDecl][]*ast.CallExpr
	// fieldOwners memoizes the declaring named type ("pkg.T") of struct
	// field vars — "" for anonymous declaring structs. Write-site
	// matching uses it to disambiguate same-named fields sharing a
	// types.Id across different structs in one package.
	fieldOwners map[*types.Var]string
	// coneCache memoizes depCone per module path: the set of module
	// functions reachable from the product's calls into it — used to
	// restrict dep-internal caller merges to product-driven paths.
	coneCache map[string]map[string]bool
	// instSet/instDisabled memoize instantiatedNamed across loaded
	// packages; instGen invalidates on extras flushes like callerCache.
	instSet      map[string]bool
	instDisabled bool
	instGen      int
	// coneBusy marks modules whose depCone is currently being computed —
	// cone checks inside the computation (dispatch narrowing looks at
	// field writes, which consult the cone) degrade to permissive instead
	// of recursing forever.
	coneBusy map[string]bool
	// exprDepth bounds structural recursion into expression trees (binary
	// chains, nested indices, giant composite literals in generated dep
	// code). hops() bounds caller climbs; this bounds AST nesting —
	// beyond it the origin is UNKNOWN, not a stack overflow.
	exprDepth int
	// evalBudget bounds total callee-frame expression evaluations within
	// one analysis session: dep-internal caller fan-out is exponential in
	// principle — past the budget the origin degrades to UNKNOWN rather
	// than burning unbounded time. 0 = inactive.
	evalBudget int
	// loadBudget bounds total packages.Load calls during a closure query session;
	// 0 = unconstrained. loadBudgetExhausted tracks when the budget was depleted.
	loadBudget          int
	loadBudgetExhausted bool
	// funcDeclCache memoizes function-declaration lookups — uncached,
	// each dep-internal call trace re-walks every file of the callee's
	// package.
	funcDeclCache map[string]funcDeclResult
	// fieldTagCache memoizes fieldConfigTagged scans — each field's tag
	// lookup re-walks the owner package's syntax; pointer key because
	// types.Var.Id() collides for same-named fields of different structs.
	fieldTagCache map[*types.Var]bool
	// fieldWritesCache memoizes fieldWriteSites scans; fieldOriginCache
	// memoizes resolved field origins by (field, remaining depth). Both
	// carry the extras generation — a freshly loaded dep package may
	// hold additional writes.
	fieldWritesCache map[*types.Var]cachedFieldWrites
	fieldOriginCache map[fieldOriginKey]cachedFieldOrigin
	mu               sync.Mutex // serializes queries; shared across cases in scan mode
	pkgs             []*packages.Package
	// extraPkgs caches dependency packages loaded on demand via loadExtra
	// (keyed by package path), so dep-internal scans (call sites, provenance)
	// can reuse their syntax without re-running packages.Load. extraOrder
	// is the insertion order — the eviction LRU for evictExtra.
	extraPkgs  map[string][]*packages.Package
	extraOrder []string
	// extraWeight memoizes each retained pattern's imported-types
	// closure size (importClosureSize of its roots) — the weight evictExtra
	// budgets against, since package count alone misses the transitively
	// imported types graph every root drags behind it.
	extraWeight map[string]int
	// extraPinned exempts a load pattern from eviction — the advisory
	// module under active closure verification must stay resident or its
	// callers vanish mid-trace (mid-verify eviction once turned every
	// resolved protojson sink position UNKNOWN).
	extraPinned map[string]bool
	// callerCache memoizes caller scans by (symbol, scope). Dependency
	// scopes grow as loadExtra pulls more packages in, so dep entries are
	// tagged with the extras generation and refreshed on a miss.
	callerCache map[callerKey]cachedCallers
	// funcValsCache memoizes resolved function-value candidates per
	// variable; gen tracks extrasGen like callerCache.
	funcValsCache map[*types.Var]funcValEntry
	funcValsIn    map[*types.Var]bool
	// fvIdx caches per-package func-value call indexes; fvIdxGen drops
	// the map when the extras generation turns over. fvBuildDepth counts
	// in-progress index builds: nested candidate resolution consults
	// existing indexes only — starting another package's build mid-build
	// recurses across the package graph (grpc-scale cones never return).
	fvIdx        map[*packages.Package]*fvPkgIndex
	fvIdxGen     int
	fvBuildDepth int
	// callersIn guards against recursive caller scans — a scan for the
	// same key mid-flight returns empty rather than looping.
	callersIn map[callerKey]bool
	extrasGen int
	// lastFreeOS throttles the post-eviction FreeOSMemory sweep — it is
	// a full GC plus madvise, far too expensive to run per load.
	lastFreeOS   time.Time
	fset         *token.FileSet
	loaded       bool
	loadErr      error
	modCacheOnce sync.Once
	modCache     string
	// importers caches the reverse import index of the full dependency
	// closure for depSiteLive's cross-module-caller bound (lazily built,
	// no syntax — import edges only).
	importers map[string][]depImporter
	// pkgModules maps every package path of the full dependency closure
	// to its owning module path ("" = stdlib) — built in the same "all"
	// load as importers.
	pkgModules map[string]string
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

// loadMode deliberately excludes NeedDeps and NeedImports: NeedDeps pulls
// the full AST+types tree of the transitive dependency graph, and
// NeedImports retains that graph as import stubs behind every loaded
// package — ~1 stub tree per retained package is what OOM-killed the host
// on large dep trees (go-getter → aws-sdk-scale). Without them roots still
// get syntax+types, dependencies resolve through export data, and the
// import graph is still reachable via pkg.Types.Imports() — which is all
// the analysis needs: dependency syntax is loaded only for packages named
// by a loadExtra pattern.
const loadMode = packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
	packages.NeedTypes | packages.NeedTypesInfo | packages.NeedModule

func (ix *Index) load(ctx context.Context) error {
	if ctx != nil {
		ix.activeCtx = ctx
	}
	if ix.loaded {
		return ix.loadErr
	}
	ix.loaded = true
	ix.fset = token.NewFileSet()
	cfg := &packages.Config{
		Mode:    loadMode,
		Dir:     ix.Dir,
		Fset:    ix.fset,
		Env:     append(os.Environ(), append(buildEnv(ix.Build), ix.Env...)...),
		Context: ctx,
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

// ctxOr prefers the caller's context; a bare Background (internal helpers
// that do not receive one) falls back to the active query context so the
// memory watchdog's cancellation still reaches subprocess loads.
func (ix *Index) ctxOr(ctx context.Context) context.Context {
	if ctx != nil && ctx != context.Background() && ctx != context.TODO() {
		return ctx
	}
	if ix.activeCtx != nil {
		return ix.activeCtx
	}
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// loadExtra loads additional root patterns (e.g. the vulnerable dependency
// package) into the same fileset so its syntax is available for reading.
// Results are cached per pattern: dep packages are reused by dep-internal
// call-site and provenance scans.
func (ix *Index) loadExtra(ctx context.Context, patterns ...string) ([]*packages.Package, error) {
	ctx = ix.ctxOr(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	key := strings.Join(patterns, "|")
	if pkgs, ok := ix.extraPkgs[key]; ok {
		return pkgs, nil
	}
	if ix.loadBudget > 0 {
		ix.loadBudget--
		if ix.loadBudget == 0 {
			ix.loadBudgetExhausted = true
		}
	} else if ix.loadBudgetExhausted {
		return nil, fmt.Errorf("closure query package load budget exhausted")
	}
	cfg := &packages.Config{
		Mode:    loadMode,
		Dir:     ix.Dir,
		Fset:    ix.fset,
		Env:     append(os.Environ(), append(buildEnv(ix.Build), ix.Env...)...),
		Context: ctx,
	}
	if len(ix.Build.BuildTags) > 0 {
		cfg.BuildFlags = []string{"-tags", strings.Join(ix.Build.BuildTags, ",")}
	}
	pkgs, err := packages.Load(cfg, patterns...)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if ix.extraPkgs == nil {
		ix.extraPkgs = map[string][]*packages.Package{}
	}
	// Bound retained dependency graphs: each entry holds a full AST+types
	// tree plus the types graph of its transitively imported packages,
	// so accumulating packages is what blew the host's memory on large
	// dep trees (go-getter → aws-sdk-scale import closures). Extras are
	// reloadable — evict the oldest patterns over budget and let callers
	// re-load the ones they still need.
	ix.extraPkgs[key] = pkgs
	ix.extraOrder = append(ix.extraOrder, key)
	if ix.extraWeight == nil {
		ix.extraWeight = map[string]int{}
	}
	w := 0
	for _, p := range pkgs {
		w += importClosureSize(p.Types)
	}
	ix.extraWeight[key] = w
	ix.evictExtra()
	ix.extrasGen++
	ix.classifyCache = nil
	ix.paramCache = nil
	return pkgs, nil
}

// importClosureSize counts the types packages transitively imported by
// tp — the retained memory a loaded package drags behind it via
// types.Package.Imports(). tp=nil weighs 0.
func importClosureSize(tp *types.Package) int {
	if tp == nil {
		return 0
	}
	seen := map[*types.Package]bool{tp: true}
	stack := []*types.Package{tp}
	n := 0
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, imp := range p.Imports() {
			if imp != nil && !seen[imp] {
				seen[imp] = true
				stack = append(stack, imp)
				n++
			}
		}
	}
	return n
}

// evictExtra drops the oldest loaded patterns until the retained package
// count fits the budget — never the newest entry, which the caller is
// about to use. Dep-caller scans cover only retained extras, so an
// evicted package simply shrinks later scans (conservative direction:
// fewer sites resolved, more UNKNOWN).
func (ix *Index) evictExtra() {
	total, files, imports := 0, 0, 0
	unpinnedTotal, unpinnedFiles, unpinnedImports := 0, 0, 0
	unpinnedLoads := 0
	for pat, pkgs := range ix.extraPkgs {
		pTotal := len(pkgs)
		pFiles := 0
		for _, p := range pkgs {
			pFiles += len(p.GoFiles)
		}
		pImports := ix.extraWeight[pat]
		total += pTotal
		files += pFiles
		imports += pImports
		if !ix.extraPinned[pat] {
			unpinnedTotal += pTotal
			unpinnedFiles += pFiles
			unpinnedImports += pImports
			unpinnedLoads++
		}
	}
	over := func() bool {
		return unpinnedTotal > maxExtraPkgs || unpinnedFiles > maxExtraFiles ||
			unpinnedImports > maxExtraImportClosure || unpinnedLoads > maxExtraLoads ||
			total > maxTotalExtraPkgs
	}
	if !over() {
		return
	}
	newest := ""
	if len(ix.extraOrder) > 0 {
		newest = ix.extraOrder[len(ix.extraOrder)-1]
	}
	evicted := false
	// Pinned victims rotate to the back instead of deleting — the spin
	// bound keeps the loop finite when every candidate is pinned.
	for spins := 0; len(ix.extraOrder) > 1 && over() && spins <= len(ix.extraOrder); {
		victim := ix.extraOrder[0]
		ix.extraOrder = ix.extraOrder[1:]
		if ix.extraPinned[victim] || victim == newest {
			ix.extraOrder = append(ix.extraOrder, victim)
			spins++
			continue
		}
		vpkgs, ok := ix.extraPkgs[victim]
		if !ok {
			continue
		}
		total -= len(vpkgs)
		unpinnedTotal -= len(vpkgs)
		for _, p := range vpkgs {
			files -= len(p.GoFiles)
			unpinnedFiles -= len(p.GoFiles)
		}
		imports -= ix.extraWeight[victim]
		unpinnedImports -= ix.extraWeight[victim]
		unpinnedLoads--
		delete(ix.extraWeight, victim)
		delete(ix.extraPkgs, victim)
		evicted = true
	}
	if evicted {
		for k := range ix.callerCache {
			if k.dep {
				delete(ix.callerCache, k) // entries point at evicted ASTs
			}
		}
		// Every cache that retains AST/package references must drop —
		// otherwise evicted packages stay alive through map entries and
		// the budget bounds nothing.
		ix.funcDeclCache = nil
		ix.assignCache = nil
		ix.callListCache = nil
		ix.fieldTagCache = nil
		ix.fieldWritesCache = nil
		ix.fieldOriginCache = nil
		ix.fieldOwners = nil
		ix.funcValsCache = nil
		ix.fvIdx = nil
		ix.classifyCache = nil
		// The runtime holds freed heap for reuse until SetMemoryLimit
		// pressure forces scavenging — under a watchdog that counts
		// HeapSys, idle garbage looks like retained memory. Hand it back
		// once the heap is large; throttle — FreeOSMemory is a full GC.
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		if m.HeapSys > 1<<30 && time.Since(ix.lastFreeOS) > time.Second {
			debug.FreeOSMemory()
			ix.lastFreeOS = time.Now()
		}
	}
}

// pinExtra exempts a retained load pattern from eviction — used for the
// advisory module a closure is actively verifying. Only reasonably sized
// patterns can pin: an aws-scale module pinned behind the memory budget
// would defeat it, so huge patterns stay evictable (their closure stays
// UNKNOWN — conservative).
func (ix *Index) pinExtra(pattern string) {
	pkgs, ok := ix.extraPkgs[pattern]
	if !ok || len(pkgs) > maxPinnedPkgs {
		return
	}
	if ix.extraPinned == nil {
		ix.extraPinned = map[string]bool{}
	}
	ix.extraPinned[pattern] = true
}

func (ix *Index) pinExtraScoped(pattern string) func() {
	wasPinned := ix.extraPinned[pattern]
	ix.pinExtra(pattern)
	return func() {
		if !wasPinned {
			delete(ix.extraPinned, pattern)
		}
	}
}

// extrasFor returns cached dependency packages matching pkgPath (loaded
// via loadExtra), or nil when the package was never loaded.
func (ix *Index) extrasFor(pkgPath string) []*packages.Package {
	var out []*packages.Package
	for _, pkgs := range ix.extraPkgs {
		for _, p := range pkgs {
			if p.PkgPath == pkgPath {
				out = append(out, p)
			}
		}
	}
	return out
}

// allExtras returns every dependency package loaded so far — used by
// dep-internal scans that must look beyond product roots.
func (ix *Index) allExtras() []*packages.Package {
	var out []*packages.Package
	for _, pkgs := range ix.extraPkgs {
		out = append(out, pkgs...)
	}
	return out
}

// isProductPkg reports whether pkg is one of the ./... product roots.
// Dependency packages (module cache, replaced local deps) are not product
// even when their path looks similar — provenance scans use this to keep
// product-scope and dep-scope callers apart.
func (ix *Index) isProductPkg(pkg *packages.Package) bool {
	for _, p := range ix.pkgs {
		if p == pkg {
			return true
		}
	}
	return false
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

// IsCheckMember reports whether a method name suggests a validation, verification,
// or authorization check whose omission is itself the vulnerable behavior
// (missing-call shape like GO-2020-0017 MapClaims.VerifyAudience).
// Non-check methods (action sinks like SendFile, ServeFile, Exec, Write) are
// execution sites where deadness proves the vulnerable code is never executed.
func IsCheckMember(name string) bool {
	return isCheckMember(name)
}

func isCheckMember(name string) bool {
	checkPrefixes := []string{"Verify", "Validate", "Check", "Authenticate", "Authorize", "Is", "Has"}
	for _, p := range checkPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
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
	return ix.productRefsTo(ref), nil
}

// productRefsTo scans product packages for references to ref — calls,
// value reads/writes and address-takes included, since a ref bound into a
// func value is an invocation the static call scan cannot see.
func (ix *Index) productRefsTo(ref domain.SymbolRef) []domain.CallSite {
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
	return out
}

// CallSiteRef pairs the exported CallSite with its internal AST handle.
type CallSiteRef struct {
	Site      domain.CallSite
	call      *ast.CallExpr
	enclosing *ast.FuncDecl
	pkg       *packages.Package
	// possible marks a caller site whose target set may be incomplete.
	possible bool
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
	return ix.findCallSitesIn(ix.pkgs, ref), nil
}

// findCallSitesIn scans every file of pkgs for calls to ref. Files are
// scanned in parallel — the trace loop calls this repeatedly, and AST
// scans are the hot path on real dependency trees. Results concatenate in
// the original (pkg, file) order, so the output is identical to a
// sequential scan.
func (ix *Index) findCallSitesIn(pkgs []*packages.Package, ref domain.SymbolRef) []CallSiteRef {
	type fileJob struct {
		pkg  *packages.Package
		file *ast.File
	}
	var jobs []fileJob
	for _, pkg := range pkgs {
		if pkg.TypesInfo == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			jobs = append(jobs, fileJob{pkg, f})
		}
	}
	perFile := make([][]CallSiteRef, len(jobs))
	workers := runtime.GOMAXPROCS(0)
	if workers > len(jobs) {
		workers = len(jobs)
	}
	if workers > 1 {
		var wg sync.WaitGroup
		next := make(chan int, workers)
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range next {
					j := jobs[i]
					perFile[i] = ix.scanFileForCalls(j.pkg, j.file, ref)
				}
			}()
		}
		for i := range jobs {
			next <- i
		}
		close(next)
		wg.Wait()
	} else {
		for i, j := range jobs {
			perFile[i] = ix.scanFileForCalls(j.pkg, j.file, ref)
		}
	}
	var out []CallSiteRef
	for _, refs := range perFile {
		out = append(out, refs...)
	}
	return out
}

// scanFileForCalls finds call sites of ref within one syntax file —
// read-only, safe for concurrent use across files.
func (ix *Index) scanFileForCalls(pkg *packages.Package, f *ast.File, ref domain.SymbolRef) []CallSiteRef {
	var out []CallSiteRef
	info := pkg.TypesInfo
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
	return out
}

// FindDepCallers locates call sites of the symbol inside the dependency
// packages themselves — for unexported subjects that product code cannot
// name (peer-driven library internals). The subject's package is loaded on
// demand; unexported callers can only live in that same package.
func (ix *Index) FindDepCallers(ctx context.Context, ref domain.SymbolRef) ([]domain.CallSite, error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	refs, err := ix.findDepCallSites(ctx, ref)
	if err != nil {
		return nil, err
	}
	out := make([]domain.CallSite, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Site)
	}
	return out, nil
}

func (ix *Index) findDepCallSites(ctx context.Context, ref domain.SymbolRef) ([]CallSiteRef, error) {
	pkgs, err := ix.loadExtra(ctx, ref.Package)
	if err != nil {
		return nil, err
	}
	// Widen to the subject's whole module when it is known — a caller in
	// a sibling package is as much a dep caller as one in the subject's
	// own package. depModuleCallSites falls back to this function when
	// the module is unknown.
	mod := ""
	for _, p := range pkgs {
		if p.PkgPath == ref.Package && p.Module != nil {
			mod = p.Module.Path
			break
		}
	}
	if mod == "" {
		return ix.findCallSitesIn(ix.extrasFor(ref.Package), ref), nil
	}
	return ix.depModuleCallSites(ctx, ref, mod)
}

// DepInvocationState reports how the subject's own module uses it:
// dep-internal call sites of the subject that a live caller chain can
// reach (a dead caller cannot resurrect the subject — deadness is
// decided transitively, see depSiteLive), and — when the subject is a
// method never invoked there — whether sibling methods on the same
// receiver type ARE invoked inside the dependency. A live receiver
// pipeline whose check member is never called is a missing-call shape
// (the validation does not run), not dead code: deadness of that member
// cannot prove the absence of the vulnerable behavior.
//
// Callers are enumerated across the subject's whole module; when the
// subject is exported and other dep modules import its package, the
// caller set is unbounded (unbounded=true) — absence of callers within
// the module then cannot ground a negative either.
func (ix *Index) DepInvocationState(ctx context.Context, ref domain.SymbolRef) (callers int, siblingLive, unbounded bool, err error) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if _, err := ix.loadExtra(ctx, ref.Package); err != nil {
		return 0, false, false, err
	}
	subjPkgs := ix.extrasFor(ref.Package)
	mod := ""
	for _, p := range subjPkgs {
		if p.Module != nil {
			mod = p.Module.Path
			break
		}
	}
	_, name := splitSymbol(ref.Symbol)
	if ast.IsExported(name) {
		importers, ierr := ix.depImporters(ctx)
		if ierr != nil {
			unbounded = true
		} else {
			var otherPkgs []string
			for _, im := range importers[ref.Package] {
				if !ix.isProductPath(im.path) && im.module != mod {
					otherPkgs = append(otherPkgs, im.path)
				}
			}
			if len(otherPkgs) > 0 {
				if len(otherPkgs) <= 16 {
					for _, op := range otherPkgs {
						opLoaded, lerr := ix.loadExtra(ctx, op)
						if lerr != nil {
							unbounded = true
							break
						}
						otherSites := ix.findCallSitesIn(opLoaded, ref)
						for _, os := range otherSites {
							if ix.depSiteLive(ctx, os, depLiveFuel, map[string]bool{}) {
								callers++
							}
						}
					}
				} else {
					unbounded = true
				}
			}
		}
	}
	sites, err := ix.depModuleCallSites(ctx, ref, mod)
	if err != nil {
		return 0, false, unbounded, err
	}
	for _, s := range sites {
		if ix.depSiteLive(ctx, s, depLiveFuel, map[string]bool{}) {
			callers++
		}
	}
	if callers > 0 || unbounded {
		return callers, false, unbounded, nil
	}
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" || !isCheckMember(name) {
		return 0, false, false, nil
	}
	pkgs := ix.extrasFor(ref.Package)
	if mod != "" {
		pkgs = ix.modulePkgs(mod)
	}
	for _, dep := range pkgs {
		if dep.Types == nil || dep.TypesInfo == nil {
			continue
		}
		tn, ok := dep.Types.Scope().Lookup(typeName).(*types.TypeName)
		if !ok {
			continue
		}
		named := mustNamed(tn)
		if named == nil {
			continue
		}
		ms := types.NewMethodSet(types.NewPointer(named))
		for i := 0; i < ms.Len(); i++ {
			m := ms.At(i).Obj()
			if m.Name() == name {
				continue
			}
			mref := domain.SymbolRef{Package: ref.Package, Symbol: typeName + "." + m.Name()}
			for _, s := range ix.findCallSitesIn(pkgs, mref) {
				if ix.depSiteLive(ctx, s, depLiveFuel, map[string]bool{}) {
					return 0, true, false, nil
				}
			}
		}
	}
	return 0, false, false, nil
}

// ReceiverPipelines finds sibling methods on the receiver type of ref that are
// live in the dependency / reachable from callers (e.g. MapClaims.Valid).
func (ix *Index) ReceiverPipelines(ctx context.Context, ref domain.SymbolRef) ([]domain.SymbolRef, error) {
	if ix == nil {
		return nil, nil
	}
	typeName, name := splitSymbol(ref.Symbol)
	if typeName == "" || !isCheckMember(name) {
		return nil, nil
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if _, err := ix.loadExtra(ctx, ref.Package); err != nil {
		return nil, err
	}
	subjPkgs := ix.extrasFor(ref.Package)
	mod := ""
	for _, p := range subjPkgs {
		if p.Module != nil {
			mod = p.Module.Path
			break
		}
	}
	pkgs := ix.extrasFor(ref.Package)
	if mod != "" {
		pkgs = ix.modulePkgs(mod)
	}

	var pipelines []domain.SymbolRef
	seen := map[string]bool{}

	for _, dep := range pkgs {
		if dep.Types == nil || dep.TypesInfo == nil {
			continue
		}
		tn, ok := dep.Types.Scope().Lookup(typeName).(*types.TypeName)
		if !ok {
			continue
		}
		named := mustNamed(tn)
		if named == nil {
			continue
		}
		var ms *types.MethodSet
		if _, isIface := named.Underlying().(*types.Interface); isIface {
			ms = types.NewMethodSet(named)
		} else {
			ms = types.NewMethodSet(types.NewPointer(named))
		}
		for i := 0; i < ms.Len(); i++ {
			m := ms.At(i).Obj()
			mName := m.Name()
			if mName == name || isCheckMember(mName) {
				continue
			}
			if mName != "Valid" && !strings.HasSuffix(mName, "Valid") {
				continue
			}
			mref := domain.SymbolRef{Package: ref.Package, Symbol: typeName + "." + mName}
			if seen[mref.Symbol] {
				continue
			}

			live := false
			if len(ix.productRefsTo(mref)) > 0 {
				live = true
			} else {
				sites := ix.findCallSitesIn(pkgs, mref)
				for _, iref := range ix.ifaceCallerRefs(mref) {
					sites = append(sites, ix.findCallSitesIn(pkgs, iref)...)
				}
				for _, s := range sites {
					if ix.depSiteLive(ctx, s, depLiveFuel, map[string]bool{}) {
						live = true
						break
					}
				}
			}

			if live {
				seen[mref.Symbol] = true
				pipelines = append(pipelines, mref)
			}
		}
	}
	return pipelines, nil
}

// modulePkgs returns the extras of one module — sibling-method scans
// must see call sites in every package of the subject's module, not only
// its own.
func (ix *Index) modulePkgs(mod string) []*packages.Package {
	var out []*packages.Package
	for _, p := range ix.allExtras() {
		if p.Module != nil && p.Module.Path == mod {
			out = append(out, p)
		}
	}
	return out
}

// depLiveFuel bounds the transitive deadness walk in depSiteLive: a
// deeper caller chain left unexplored answers live rather than guessed
// dead.
const depLiveFuel = 6

// methodInAnyInterface reports whether any interface declared in the product,
// loaded dependency packages, or well-known standard library interfaces
// declares a method with the given name. In Go, dynamic interface dispatch
// is only possible for methods that belong to an interface type.
func (ix *Index) methodInAnyInterface(name string) bool {
	switch name {
	case "Read", "Write", "Close", "Seek", "ReadAt", "WriteAt", "ReadFrom", "WriteTo",
		"ServeHTTP", "String", "Error", "Format", "Scan", "Reset", "Flush",
		"Header", "WriteHeader", "Lock", "Unlock", "RLock", "RUnlock",
		"Timeout", "Temporary", "Len", "Less", "Swap":
		return true
	}
	checkPkg := func(p *packages.Package) bool {
		if p.Types == nil {
			return false
		}
		scope := p.Types.Scope()
		for _, n := range scope.Names() {
			obj := scope.Lookup(n)
			tn, ok := obj.(*types.TypeName)
			if !ok {
				continue
			}
			if iface, ok := tn.Type().Underlying().(*types.Interface); ok {
				for i := 0; i < iface.NumMethods(); i++ {
					if iface.Method(i).Name() == name {
						return true
					}
				}
			}
		}
		return false
	}
	for _, p := range ix.pkgs {
		if checkPkg(p) {
			return true
		}
	}
	for _, p := range ix.allExtras() {
		if checkPkg(p) {
			return true
		}
	}
	return false
}

// depSiteLive reports whether the dependency call site sits on a chain
// some live code can reach. The falsifier "no product references" is
// only a valid negative when the subject is dead in the effective
// build, and a dep call site is dead only if its own caller chain dies:
// the enclosing function must have no product references, no callers
// left inside the module (recursively), and — when exported — no
// importer outside the module it could be invoked from.
func (ix *Index) depSiteLive(ctx context.Context, s CallSiteRef, fuel int, seen map[string]bool) bool {
	if s.pkg == nil || s.enclosing == nil || s.enclosing.Name == nil {
		return true // package-level/init context runs by construction
	}
	name := s.enclosing.Name.Name
	if name == "init" {
		return true
	}
	callerSym := name
	if s.enclosing.Recv != nil && len(s.enclosing.Recv.List) > 0 {
		typeName := recvDeclName(s.enclosing.Recv.List[0].Type)
		if typeName != "" {
			callerSym = typeName + "." + name
		}
	}
	key := s.pkg.PkgPath + "." + callerSym
	if seen[key] {
		return false // cycle cut — this path contributes nothing new
	}
	if fuel <= 0 {
		return true // unexplored remainder — conservative
	}
	fref := domain.SymbolRef{Package: s.pkg.PkgPath, Symbol: callerSym}
	if len(ix.productRefsTo(fref)) > 0 {
		return true // the product itself can invoke the caller
	}
	mod := ""
	if s.pkg.Module != nil {
		mod = s.pkg.Module.Path
	}
	if ast.IsExported(name) {
		importers, err := ix.depImporters(ctx)
		if err != nil {
			return true
		}
		var otherPkgs []string
		for _, im := range importers[s.pkg.PkgPath] {
			if !ix.isProductPath(im.path) && im.module != mod {
				otherPkgs = append(otherPkgs, im.path)
			}
		}
		if len(otherPkgs) > 16 {
			return true
		}
		for _, op := range otherPkgs {
			opLoaded, lerr := ix.loadExtra(ctx, op)
			if lerr != nil {
				return true
			}
			otherSites := ix.findCallSitesIn(opLoaded, fref)
			for _, os := range otherSites {
				if ix.depSiteLive(ctx, os, fuel-1, seen) {
					return true
				}
			}
		}
	}
	// Check reachability via the module's entry cone:
	if mod != "" {
		if cone := ix.depCone(mod); cone != nil {
			if !cone[key] {
				return false
			}
		} else if s.enclosing.Recv != nil && len(s.enclosing.Recv.List) > 0 && ast.IsExported(name) {
			// Interface dispatch cannot be ruled out when cone is unavailable and an interface declaring this method exists
			if ix.methodInAnyInterface(name) {
				return true
			}
		}
	} else if s.enclosing.Recv != nil && len(s.enclosing.Recv.List) > 0 && ast.IsExported(name) {
		if ix.methodInAnyInterface(name) {
			return true
		}
	}
	seen[key] = true
	defer delete(seen, key)
	inner, err := ix.depModuleCallSites(ctx, fref, mod)
	if err != nil {
		return true
	}
	for _, is := range inner {
		if is.enclosing == s.enclosing && is.pkg == s.pkg {
			continue // the site's own function cannot be its own caller
		}
		if ix.depSiteLive(ctx, is, fuel-1, seen) {
			return true
		}
	}
	return false
}

// depModuleCallSites finds call sites of ref across the subject's whole
// module, not only its own package — a caller may live in a sibling dep
// package. Without module info the scan falls back to the package.
func (ix *Index) depModuleCallSites(ctx context.Context, ref domain.SymbolRef, mod string) ([]CallSiteRef, error) {
	if mod == "" {
		return ix.findDepCallSites(ctx, ref)
	}
	pkgs, err := ix.loadExtra(ctx, mod+"/...")
	if err != nil {
		return nil, err
	}
	var scoped []*packages.Package
	for _, p := range pkgs {
		if p.PkgPath == mod || strings.HasPrefix(p.PkgPath, mod+"/") {
			scoped = append(scoped, p)
		}
	}
	return ix.findCallSitesIn(scoped, ref), nil
}

// depImporter records a package in the product's dependency graph that
// imports a given package, with the module it belongs to.
type depImporter struct {
	path   string
	module string
}

// depImporters builds the reverse import index of the whole dependency
// closure (product + deps, no syntax) so deadness checks can tell
// whether an exported dep function could be invoked from another
// module. Loaded once per index — the import graph does not change
// while extras come and go.
func (ix *Index) depImporters(ctx context.Context) (map[string][]depImporter, error) {
	if ix.importers != nil {
		return ix.importers, nil
	}
	ctx = ix.ctxOr(ctx)
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	cfg := &packages.Config{
		Mode:    packages.NeedName | packages.NeedImports | packages.NeedModule,
		Dir:     ix.Dir,
		Env:     append(os.Environ(), append(buildEnv(ix.Build), ix.Env...)...),
		Context: ctx,
	}
	if len(ix.Build.BuildTags) > 0 {
		cfg.BuildFlags = []string{"-tags", strings.Join(ix.Build.BuildTags, ",")}
	}
	pkgs, err := packages.Load(cfg, "all")
	if err != nil {
		return nil, err
	}
	m := map[string][]depImporter{}
	pm := map[string]string{}
	for _, p := range pkgs {
		mod := ""
		if p.Module != nil {
			mod = p.Module.Path
		}
		pm[p.PkgPath] = mod
		for imp := range p.Imports {
			m[imp] = append(m[imp], depImporter{path: p.PkgPath, module: mod})
		}
	}
	ix.importers = m
	ix.pkgModules = pm
	return m, nil
}

// depModuleOf returns the module a package belongs to, loading the
// reverse-import index lazily when provenance tracing runs before the
// ingress inventory. "" means product/stdlib/unresolvable.
func (ix *Index) depModuleOf(pkgPath string) string {
	if ix.pkgModules == nil {
		_, _ = ix.depImporters(ix.ctxOr(context.Background()))
	}
	return ix.pkgModules[pkgPath]
}

// importedByOtherModule reports whether pkgPath is imported by a
// dependency package outside its own module — a caller chain member
// there is not enumerable by the module-internal scans. Product-side
// importers do not count: product references are checked directly.
// Any doubt (load failure, missing importer data) answers true.
func (ix *Index) importedByOtherModule(ctx context.Context, pkgPath, mod string) bool {
	m, err := ix.depImporters(ctx)
	if err != nil {
		return true
	}
	for _, im := range m[pkgPath] {
		if ix.isProductPath(im.path) || im.module == mod {
			continue
		}
		return true
	}
	return false
}

// callerScope returns the packages to search for callers of a function
// declared in pkg: product packages for product code; for dependency code
// the union of the dep package and product roots (an exported dep function
// may be invoked from either side).
func (ix *Index) callerScope(pkg *packages.Package) []*packages.Package {
	if ix.isProductPkg(pkg) {
		return ix.pkgs
	}
	return append(append([]*packages.Package{}, ix.allExtras()...), ix.pkgs...)
}

// maxExtraLoads bounds how many dependency-load patterns the index
// retains at once; maxExtraPkgs bounds the retained package count;
// maxExtraFiles bounds the retained file count; maxExtraImportClosure
// bounds the total transitively-imported types packages held behind
// retained roots — the dominant hidden mass (every load re-creates the
// types graph of its whole import closure, so an aws-scale root can cost
// hundreds of MB in imported types while counting as one package).
// maxCallerCache bounds memoized caller scans.
const (
	maxExtraLoads         = 64
	maxExtraPkgs          = 96
	maxExtraFiles         = 1000
	maxExtraImportClosure = 5000
	maxPinnedPkgs         = 128
	maxTotalExtraPkgs     = 224
	maxCallerCache        = 8192
	maxClassifyCache      = 65536
	maxAuxCache           = 16384
	// maxTxBuf caps the transformation records one trace accumulates —
	// audit detail, not correctness input.
	maxTxBuf = 8192
)

// callerKey identifies one caller scan: the symbol looked up and which
// scope callerScope picked (product roots only, or the dep+product union).
type callerKey struct {
	ref domain.SymbolRef
	dep bool
}

// classifyKey addresses one classify evaluation: the expression node in
// its enclosing function, the package that type-checked it, and the
// remaining caller-hop depth.
type classifyKey struct {
	pkg   *packages.Package
	enc   *ast.FuncDecl
	expr  ast.Expr
	depth int
}

type classifyResult struct {
	origin domain.DataOrigin
	why    string
}

type assignKey struct {
	enc *ast.FuncDecl
	obj types.Object
}

// cachedCallers records a caller scan. Dep-scope entries expire when the
// extras generation advances — a freshly loaded dep package may hold
// additional callers of the same symbol.
type cachedCallers struct {
	gen  int
	refs []CallSiteRef
}

// callersOf scans for call sites of ref across pkg's caller scope,
// memoized. Deep traces revisit the same enclosing functions repeatedly;
// without this every hop re-walked every loaded package's syntax.
func (ix *Index) callersOf(pkg *packages.Package, ref domain.SymbolRef) []CallSiteRef {
	dep := !ix.isProductPkg(pkg)
	gen := ix.extrasGen
	key := callerKey{ref: ref, dep: dep}
	if c, ok := ix.callerCache[key]; ok && (!dep || c.gen == ix.extrasGen) {
		return c.refs
	}
	if ix.callersIn == nil {
		ix.callersIn = map[callerKey]bool{}
	}
	if ix.callersIn[key] {
		return nil
	}
	ix.callersIn[key] = true
	scope := ix.callerScope(pkg)
	refs := ix.findCallSitesIn(scope, ref)
	// A caller of an interface method is a caller of every implementation:
	// `g.GetFile(...)` where g is a Getter invokes GitGetter.GetFile even
	// though no call site names it. Dispatch through registries
	// (go-getter's getters map, amqp's reader iface) is invisible to a
	// concrete-method-only scan.
	for _, iref := range ix.ifaceCallerRefs(ref) {
		for _, r := range ix.findCallSitesIn(scope, iref) {
			// An interface-dispatch site counts only when it can actually
			// dispatch to ref's impl: `g := registry[key]` with an
			// evaluable key reaches just the registered impls at the key's
			// values. Unevaluable keys keep the site (unknown-biased).
			if t, _ := splitSymbol(ref.Symbol); t != "" {
				if set := ix.dispatchImpls(r.pkg, r.enclosing, r.call); set != nil && !set[t] {
					continue
				}
			}
			if !dupCallSite(refs, r) {
				refs = append(refs, r)
			}
		}
	}
	// Function-value dispatch sites: `f(...)` where f is a func-typed
	// variable — invisible to the name-based scans above. Sites whose
	// candidate set contains ref, or whose set is incomplete while the
	// signature matches, count as callers (may-dispatch is a writer).
	for _, r := range ix.funcValueCallSites(scope, ref, ix.funcSigOfRef(ref)) {
		if !dupCallSite(refs, r) {
			refs = append(refs, r)
		}
	}
	delete(ix.callersIn, key)
	if ix.extrasGen != gen {
		if len(refs) == 0 {
			return []CallSiteRef{{possible: true}}
		}
		for i := range refs {
			refs[i].possible = true
		}
		return refs
	}
	if ix.callerCache == nil {
		ix.callerCache = map[callerKey]cachedCallers{}
	}
	if len(ix.callerCache) >= maxCallerCache {
		// Entries are recomputable — a full map is a memory leak shape,
		// not an optimization.
		ix.callerCache = map[callerKey]cachedCallers{}
	}
	ix.callerCache[key] = cachedCallers{gen: gen, refs: refs}
	return refs
}

// dupCallSite reports whether refs already contains a CallSiteRef for the
// same AST call node.
func dupCallSite(refs []CallSiteRef, r CallSiteRef) bool {
	for _, x := range refs {
		if x.call == r.call {
			return true
		}
	}
	return false
}

// ifaceCallerRefs returns SymbolRefs of interface methods that ref (a
// concrete method pkg.T.M) implements — call sites of those interface
// methods dispatch into T.M. Both the concrete type and the interfaces
// are looked up in the loaded packages; nothing found means no extra
// callers, not no callers.
func (ix *Index) ifaceCallerRefs(ref domain.SymbolRef) []domain.SymbolRef {
	typeName, method := splitSymbol(ref.Symbol)
	if typeName == "" {
		return nil
	}
	var T *types.Named
	for _, p := range append(ix.allExtras(), ix.pkgs...) {
		if p.PkgPath != ref.Package || p.Types == nil {
			continue
		}
		if tn, ok := p.Types.Scope().Lookup(typeName).(*types.TypeName); ok {
			T, _ = tn.Type().(*types.Named)
		}
	}
	if T == nil {
		return nil
	}
	// A concrete type that is never instantiated anywhere in loaded code
	// cannot be the dynamic target of an interface call — its interface
	// callers would merge provenance from frames that never run (mocks
	// shipped in non-test files, dead registry alternatives). Skipped
	// entirely when dynamic materialization is present.
	if inst, narrow := ix.instantiated(); narrow && !inst[namedKey(T)] {
		return nil
	}
	var out []domain.SymbolRef
	for _, p := range append(ix.allExtras(), ix.pkgs...) {
		if p.Types == nil {
			continue
		}
		for _, name := range p.Types.Scope().Names() {
			tn, ok := p.Types.Scope().Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			named, ok := tn.Type().(*types.Named)
			if !ok {
				continue
			}
			iface, ok := named.Underlying().(*types.Interface)
			if !ok || !types.Implements(types.NewPointer(T), iface) {
				continue
			}
			for i := 0; i < iface.NumMethods(); i++ {
				if iface.Method(i).Name() == method {
					out = append(out, domain.SymbolRef{
						Package: p.PkgPath, Symbol: name + "." + method})
				}
			}
		}
	}
	return out
}

// isProductPath reports whether pkgPath is one of the product roots.
func (ix *Index) isProductPath(pkgPath string) bool {
	for _, p := range ix.pkgs {
		if p.PkgPath == pkgPath {
			return true
		}
	}
	return false
}

// memberScope returns the packages to scan for writes to a struct field
// declared in pkgPath — the same product-vs-dep rule as callerScope.
func (ix *Index) memberScope(pkgPath string) []*packages.Package {
	if ix.isProductPath(pkgPath) {
		return ix.pkgs
	}
	return append(append([]*packages.Package{}, ix.allExtras()...), ix.pkgs...)
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

// modCacheDir resolves the Go module cache root: GOMODCACHE (index env
// overrides first, then the process env) else GOPATH[0]/pkg/mod. Empty
// when unresolvable.
func (ix *Index) modCacheDir() string {
	ix.modCacheOnce.Do(func() {
		for _, e := range ix.Env {
			if v, ok := strings.CutPrefix(e, "GOMODCACHE="); ok && v != "" {
				ix.modCache = v
				return
			}
		}
		if v := os.Getenv("GOMODCACHE"); v != "" {
			ix.modCache = v
			return
		}
		var gopath string
		for _, e := range ix.Env {
			if v, ok := strings.CutPrefix(e, "GOPATH="); ok && v != "" {
				gopath = v
			}
		}
		if gopath == "" {
			gopath = os.Getenv("GOPATH")
		}
		if gopath == "" {
			gopath = build.Default.GOPATH
		}
		if gopath != "" {
			ix.modCache = filepath.Join(filepath.SplitList(gopath)[0], "pkg", "mod")
		}
	})
	return ix.modCache
}

// pathAllowed reports whether an absolute path is inside the analyzed
// repository or inside the Go module cache — the two scopes the agent may
// legitimately read (vulnerable dependency source is evidence too).
func (ix *Index) pathAllowed(full string) bool {
	if base, err := filepath.Abs(ix.Dir); err == nil {
		if rel, err := filepath.Rel(base, full); err == nil &&
			!strings.HasPrefix(rel, "..") && rel != ".." {
			return true
		}
	}
	if mc := ix.modCacheDir(); mc != "" {
		if mabs, err := filepath.Abs(mc); err == nil {
			if rel, err := filepath.Rel(mabs, full); err == nil &&
				!strings.HasPrefix(rel, "..") {
				return true
			}
		}
	}
	// Fallback marker for unconventional module caches (mirrors the
	// reviewer's source-scope rule).
	return strings.Contains(full, string(filepath.Separator)+
		"pkg"+string(filepath.Separator)+"mod"+string(filepath.Separator))
}

// ReadSource returns lines [start,end] (1-based, inclusive; 0 = whole
// file) of a file inside the analyzed repository or the Go module cache.
// Paths are confined to those scopes — the agent must not read arbitrary
// filesystem locations.
func (ix *Index) ReadSource(_ context.Context, file string, start, end int) (string, error) {
	clean := filepath.Clean(file)
	abs := clean
	if !filepath.IsAbs(clean) {
		abs = filepath.Join(ix.Dir, clean)
	}
	full, err := filepath.Abs(abs)
	if err != nil {
		return "", err
	}
	if !ix.pathAllowed(full) {
		return "", fmt.Errorf("path %s escapes the analyzed repository/module cache", file)
	}
	b, err := os.ReadFile(full)
	if err != nil {
		return "", err
	}
	lines := strings.Split(string(b), "\n")
	if start <= 0 {
		start = 1
	}
	if end <= 0 || end > len(lines) {
		end = len(lines)
	}
	if start > len(lines) {
		return "", fmt.Errorf("start line %d beyond file length %d", start, len(lines))
	}
	return strings.Join(lines[start-1:end], "\n"), nil
}

const maxSearchMatches = 64

// SearchSource regex-searches the loaded Go files — the product's own
// sources plus dependency sources resolved from the module cache (same
// confinement as ReadSource). Returns up to maxSearchMatches
// "file:line: text" matches; a bad regex is an error.
func (ix *Index) SearchSource(ctx context.Context, pattern string) ([]string, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("bad pattern: %w", err)
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ctx); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []string
	for _, pkg := range ix.pkgs {
		for _, f := range pkg.Syntax {
			fpos := ix.fset.Position(f.Pos())
			name := fpos.Filename
			if seen[name] {
				continue
			}
			seen[name] = true
			if !ix.pathAllowed(name) {
				continue // source outside repository/module cache
			}
			data, err := os.ReadFile(name)
			if err != nil {
				continue
			}
			for i, ln := range strings.Split(string(data), "\n") {
				if re.MatchString(ln) {
					out = append(out, fmt.Sprintf("%s:%d: %s", name, i+1, strings.TrimSpace(ln)))
					if len(out) >= maxSearchMatches {
						return out, nil
					}
				}
			}
		}
	}
	return out, nil
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

// FindListeners reports product functions that start network listeners or
// servers — i.e. functions whose body calls a listener primitive
// (kb().ListenerPrimitives). Bytes consumed by a reachable server-side
// transport originate from remote peers, not from product code.
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
					for _, prim := range ix.kb().ListenerPrimitives {
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

// ModuleUsage reports product call sites whose callee package matches the
// module path prefix. Each site carries the actual owner from the import
// graph; nested modules and unresolved owners remain visible to consumers
// but cannot count as confirmed calls into the requested module.
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
				owner := ix.depModuleOf(p)
				site := ix.siteOf(pkg, enc, call)
				site.Callee = p + "." + fn.Name()
				site.ModuleOwner = owner
				if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
					rn := strings.TrimPrefix(sig.Recv().Type().String(), "*")
					if i := strings.LastIndexByte(rn, '.'); i >= 0 {
						rn = rn[i+1:]
					}
					site.Callee = p + "." + rn + "." + fn.Name()
				}
				gated, dead, detail, _ := ix.checkCallSiteGuardLocked(ctx, site)
				site.DeadCode = dead
				if gated || dead {
					site.GatedBy = detail
				}
				out = append(out, site)
				return true
			})
		}
	}
	return out, nil
}

type opaqueSite struct {
	sig   *types.Signature
	iface *types.Interface
}

// ModuleInternalReach resolves which of the given subjects are reachable from
// the entry symbols (module API functions the product calls) through call
// edges inside the vendored module source. Returns subject key ("pkg.Symbol")
// to the discovered call chain (entry → ... → subject). Type-resolved: method
// calls match the subject only when the receiver type is the subject's.
//
// Dispatch inside the module is handled explicitly: calls through interface
// values (plugin/getter registries like go-getter's `getters[scheme].Get`)
// resolve to the interface method, and every concrete implementation in the
// module is linked interface-method → impl, so BFS can pass through.
// Calls that resolve to no function at all (func values, map-indexed
// non-interface calls) set opaque: an unreached subject then proves
// nothing — callers must treat absence as UNKNOWN, never FALSE.
func (ix *Index) ModuleInternalReach(ctx context.Context, module string, entries []string, subjects []domain.SymbolRef) (map[string][]string, bool, error) {
	fset := token.NewFileSet()
	cfg := &packages.Config{
		Mode:    loadMode,
		Dir:     ix.Dir,
		Fset:    fset,
		Env:     append(os.Environ(), append(buildEnv(ix.Build), ix.Env...)...),
		Context: ix.ctxOr(ctx),
	}
	pkgs, err := packages.Load(cfg, module+"/...")
	if err != nil {
		return nil, false, err
	}
	edges, opaqueSites := ix.moduleEdgesSites(pkgs, module)

	out := map[string][]string{}
	var unreached []domain.SymbolRef
	for _, subj := range subjects {
		target := subj.Package + "." + subj.Symbol
		found := false
		for _, e := range entries {
			if chain := bfsChain(edges, e, target); chain != nil {
				out[target] = chain
				found = true
				break
			}
		}
		if !found {
			unreached = append(unreached, subj)
		}
	}
	if len(unreached) == 0 {
		return out, false, nil
	}

	// Opaque dispatch (func values, dynamic calls) only invalidates reachability
	// if an opaque call site is actually reachable from the product's used API
	// entries AND its signature or interface is compatible with an unreached subject.
	var reachableSites []opaqueSite
	for oc, sites := range opaqueSites {
		if len(sites) == 0 {
			continue
		}
		for _, e := range entries {
			if bfsChain(edges, e, oc) != nil {
				reachableSites = append(reachableSites, sites...)
				break
			}
		}
	}
	if len(reachableSites) == 0 {
		return out, false, nil
	}

	opaque := false
	for _, subj := range unreached {
		subjObj, recvType := findSubjectObject(pkgs, subj)
		for _, site := range reachableSites {
			if isOpaqueSiteCompatible(site, subj, subjObj, recvType) {
				opaque = true
				break
			}
		}
		if opaque {
			break
		}
	}
	return out, opaque, nil
}

// findSubjectObject resolves the subject symbol to its types.Object and receiver type
// from the loaded module packages.
func findSubjectObject(pkgs []*packages.Package, subj domain.SymbolRef) (types.Object, types.Type) {
	var targetPkg *packages.Package
	for _, p := range pkgs {
		if p.PkgPath == subj.Package && p.Types != nil {
			targetPkg = p
			break
		}
	}
	if targetPkg == nil {
		return nil, nil
	}

	typeName, name := splitSymbol(subj.Symbol)
	typeName = strings.TrimSpace(typeName)
	typeName = strings.Trim(typeName, "()*")
	typeName = strings.TrimSpace(typeName)
	if typeName == "" {
		if obj := targetPkg.Types.Scope().Lookup(name); obj != nil {
			return obj, nil
		}
		for _, n := range targetPkg.Types.Scope().Names() {
			tn, ok := targetPkg.Types.Scope().Lookup(n).(*types.TypeName)
			if !ok {
				continue
			}
			nt := mustNamed(tn)
			if nt == nil {
				continue
			}
			if iface, ok := nt.Underlying().(*types.Interface); ok {
				for i := 0; i < iface.NumMethods(); i++ {
					m := iface.Method(i)
					if m.Name() == name {
						return m, nt
					}
				}
				continue
			}
			mset := types.NewMethodSet(types.NewPointer(nt))
			for i := 0; i < mset.Len(); i++ {
				m := mset.At(i).Obj()
				if m.Name() == name {
					return m, nt
				}
			}
		}
		return nil, nil
	}

	tn, ok := targetPkg.Types.Scope().Lookup(typeName).(*types.TypeName)
	if !ok {
		return nil, nil
	}
	nt := mustNamed(tn)
	if nt == nil {
		return nil, nil
	}
	if iface, ok := nt.Underlying().(*types.Interface); ok {
		for i := 0; i < iface.NumMethods(); i++ {
			m := iface.Method(i)
			if m.Name() == name {
				return m, nt
			}
		}
		return nil, nt
	}
	mset := types.NewMethodSet(types.NewPointer(nt))
	for i := 0; i < mset.Len(); i++ {
		m := mset.At(i).Obj()
		if m.Name() == name {
			return m, nt
		}
	}
	return nil, nt
}

// isOpaqueSiteCompatible checks whether an opaque call site (func variable or unlinked
// interface call) could plausibly invoke the target subject.
func isOpaqueSiteCompatible(site opaqueSite, subj domain.SymbolRef, subjObj types.Object, recvType types.Type) bool {
	if site.sig == nil && site.iface == nil {
		return true
	}
	if subjObj == nil {
		return true
	}
	fn, ok := subjObj.(*types.Func)
	if !ok {
		return false
	}
	subjSig, ok := fn.Type().(*types.Signature)
	if !ok {
		return false
	}

	if site.sig != nil {
		if sigCompatible(site.sig, subjSig) {
			return true
		}
	}
	if site.iface != nil {
		if ifaceCompatible(site.iface, subj, recvType) {
			return true
		}
	}
	return false
}

// sigCompatible reports whether an indirect function call with siteSig could
// plausibly invoke a target with subjSig (directly as a func/method value or via method expression).
func sigCompatible(siteSig, subjSig *types.Signature) bool {
	if types.Identical(siteSig, subjSig) {
		return true
	}
	resultsMatch := func(r1, r2 *types.Tuple) bool {
		if r1.Len() != r2.Len() {
			return false
		}
		for i := 0; i < r1.Len(); i++ {
			if !types.Identical(r1.At(i).Type(), r2.At(i).Type()) {
				return false
			}
		}
		return true
	}
	paramsMatch := func(p1, p2 *types.Tuple) bool {
		if p1.Len() != p2.Len() {
			return false
		}
		for i := 0; i < p1.Len(); i++ {
			if !types.Identical(p1.At(i).Type(), p2.At(i).Type()) {
				return false
			}
		}
		return true
	}

	if resultsMatch(siteSig.Results(), subjSig.Results()) {
		// Case 1: direct parameter match (package-level func or method value call)
		if paramsMatch(siteSig.Params(), subjSig.Params()) && siteSig.Variadic() == subjSig.Variadic() {
			return true
		}
		// Case 2: method expression call (first param is receiver)
		if subjSig.Recv() != nil && siteSig.Params().Len() == 1+subjSig.Params().Len() {
			firstParam := siteSig.Params().At(0).Type()
			recvT := subjSig.Recv().Type()
			recvMatch := types.Identical(firstParam, recvT) || types.Identical(firstParam, types.NewPointer(recvT))
			if !recvMatch {
				if ptr, ok := recvT.(*types.Pointer); ok {
					recvMatch = types.Identical(firstParam, ptr.Elem())
				}
			}
			if recvMatch {
				tailMatch := true
				for i := 0; i < subjSig.Params().Len(); i++ {
					if !types.Identical(siteSig.Params().At(i+1).Type(), subjSig.Params().At(i).Type()) {
						tailMatch = false
						break
					}
				}
				if tailMatch && siteSig.Variadic() == subjSig.Variadic() {
					return true
				}
			}
		}
	}
	return false
}

// ifaceCompatible reports whether an interface method dispatch on iface could
// invoke the target subject method on receiver type recvType.
func ifaceCompatible(iface *types.Interface, subj domain.SymbolRef, recvType types.Type) bool {
	if iface == nil || recvType == nil {
		return false
	}
	_, name := splitSymbol(subj.Symbol)
	hasMethod := false
	for i := 0; i < iface.NumMethods(); i++ {
		if iface.Method(i).Name() == name {
			hasMethod = true
			break
		}
	}
	if !hasMethod {
		return false
	}
	if types.Implements(recvType, iface) {
		return true
	}
	if types.Implements(types.NewPointer(recvType), iface) {
		return true
	}
	return false
}

// moduleEdges builds the intra-module call graph: caller-qualified-name ->
// set of callee-qualified-names, plus interface-method -> implementation
// edges for every module-local impl of invoked interface methods. The
// map returns the set of qualified caller names that contain opaque dispatch —
// calls resolving to no function at all (func values).
func (ix *Index) moduleEdges(pkgs []*packages.Package, module string) (map[string]map[string]bool, map[string]bool) {
	edges, sites := ix.moduleEdgesSites(pkgs, module)
	callers := make(map[string]bool, len(sites))
	for k, v := range sites {
		if len(v) > 0 {
			callers[k] = true
		}
	}
	return edges, callers
}

func (ix *Index) moduleEdgesSites(pkgs []*packages.Package, module string) (map[string]map[string]bool, map[string][]opaqueSite) {
	edges := map[string]map[string]bool{}
	opaqueSites := map[string][]opaqueSite{}
	addOpaque := func(caller string, site opaqueSite) {
		for _, existing := range opaqueSites[caller] {
			sigMatch := (existing.sig == site.sig) || (existing.sig != nil && site.sig != nil && types.Identical(existing.sig, site.sig))
			ifaceMatch := (existing.iface == site.iface)
			if sigMatch && ifaceMatch {
				return
			}
		}
		opaqueSites[caller] = append(opaqueSites[caller], site)
	}
	// Interface dispatch call sites, recorded for per-site impl narrowing:
	// a site `g.M()` where g = registry[key] with an evaluable key reaches
	// only the impls registered at the key's values, not every impl.
	type ifaceSite struct {
		pkg *packages.Package
		enc *ast.FuncDecl

		call *ast.CallExpr
	}
	ifaceSites := map[*types.Named]map[string][]ifaceSite{}
	addEdge := func(key, callee string) {
		if edges[key] == nil {
			edges[key] = map[string]bool{}
		}
		edges[key][callee] = true
	}
	fieldOwners := map[*types.Var]string{}
	indexScope := func(scope *types.Scope) {
		if scope == nil {
			return
		}
		for _, name := range scope.Names() {
			tn, ok := scope.Lookup(name).(*types.TypeName)
			if !ok {
				continue
			}
			st, ok := tn.Type().Underlying().(*types.Struct)
			if !ok {
				continue
			}
			pp := ""
			if tn.Pkg() != nil {
				pp = tn.Pkg().Path()
			}
			owner := pp + "." + tn.Name()
			for i := 0; i < st.NumFields(); i++ {
				f := st.Field(i)
				fieldOwners[f] = owner + "." + f.Name()
			}
		}
	}
	for _, pkg := range pkgs {
		if pkg.Types != nil {
			indexScope(pkg.Types.Scope())
			for _, imp := range pkg.Types.Imports() {
				indexScope(imp.Scope())
			}
		}
	}

	structFieldKey := func(f *types.Var, recv types.Type) string {
		if k, ok := fieldOwners[f]; ok && k != "" {
			return k
		}
		if recv != nil {
			if ptr, ok := recv.(*types.Pointer); ok {
				recv = ptr.Elem()
			}
			if named, ok := recv.(*types.Named); ok && named.Obj() != nil {
				pp := ""
				if named.Obj().Pkg() != nil {
					pp = named.Obj().Pkg().Path()
				}
				return pp + "." + named.Obj().Name() + "." + f.Name()
			}
		}
		if f.Pkg() != nil {
			return f.Pkg().Path() + ".." + f.Name()
		}
		return f.Name()
	}

	pkgVarKey := func(v *types.Var) string {
		if v.Pkg() != nil {
			return v.Pkg().Path() + "." + v.Name()
		}
		return v.Name()
	}

	structFieldFuncs := map[string][]*types.Func{}
	pkgVarFuncs := map[string][]*types.Func{}

	addFunc := func(m map[string][]*types.Func, key string, fn *types.Func) bool {
		if fn == nil || key == "" {
			return false
		}
		for _, existing := range m[key] {
			if existing == fn {
				return false
			}
		}
		m[key] = append(m[key], fn)
		return true
	}

	var extractTargetFuncs func(info *types.Info, encDecl *ast.FuncDecl, rhs ast.Expr, depth int) []*types.Func
	extractTargetFuncs = func(info *types.Info, encDecl *ast.FuncDecl, rhs ast.Expr, depth int) []*types.Func {
		if depth > 5 || rhs == nil || info == nil {
			return nil
		}
		for {
			if p, ok := rhs.(*ast.ParenExpr); ok {
				rhs = p.X
				continue
			}
			break
		}
		var out []*types.Func
		switch e := rhs.(type) {
		case *ast.SelectorExpr:
			if sel, ok := info.Selections[e]; ok {
				if fn, ok := sel.Obj().(*types.Func); ok {
					out = append(out, fn)
				} else if sel.Kind() == types.FieldVal {
					if fv, ok := sel.Obj().(*types.Var); ok {
						if _, isSig := fv.Type().Underlying().(*types.Signature); isSig {
							key := structFieldKey(fv, sel.Recv())
							out = append(out, structFieldFuncs[key]...)
						}
					}
				}
			}
			if len(out) == 0 {
				if fn, ok := info.ObjectOf(e.Sel).(*types.Func); ok {
					out = append(out, fn)
				} else if v, ok := info.ObjectOf(e.Sel).(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					out = append(out, pkgVarFuncs[pkgVarKey(v)]...)
				}
			}
		case *ast.Ident:
			if fn, ok := info.ObjectOf(e).(*types.Func); ok {
				out = append(out, fn)
			} else if v, ok := info.ObjectOf(e).(*types.Var); ok {
				if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
					out = append(out, pkgVarFuncs[pkgVarKey(v)]...)
				} else if encDecl != nil {
					if _, isSig := v.Type().Underlying().(*types.Signature); isSig {
						for _, r := range assignRHS(info, encDecl, v) {
							out = append(out, extractTargetFuncs(info, encDecl, r.expr, depth+1)...)
						}
					}
				}
			}
		case *ast.CallExpr:
			if len(e.Args) == 1 {
				if tv, ok := info.Types[e.Fun]; ok && tv.IsType() {
					out = append(out, extractTargetFuncs(info, encDecl, e.Args[0], depth+1)...)
				}
			}
		}
		return out
	}

	// Pre-pass: collect struct field and package-level function assignments with fixed-point iteration
	for iter := 0; iter < 5; iter++ {
		added := 0
		for _, pkg := range pkgs {
			info := pkg.TypesInfo
			if info == nil {
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
						for i, name := range vs.Names {
							if i >= len(vs.Values) {
								continue
							}
							obj := info.ObjectOf(name)
							v, ok := obj.(*types.Var)
							if !ok {
								continue
							}
							if _, isSig := v.Type().Underlying().(*types.Signature); !isSig {
								continue
							}
							for _, target := range extractTargetFuncs(info, nil, vs.Values[i], 0) {
								if addFunc(pkgVarFuncs, pkgVarKey(v), target) {
									added++
								}
							}
						}
					}
				}
				var encDecl *ast.FuncDecl
				ast.Inspect(f, func(n ast.Node) bool {
					if fn, ok := n.(*ast.FuncDecl); ok {
						encDecl = fn
						return true
					}
					if lit, ok := n.(*ast.CompositeLit); ok {
						typ := info.Types[lit].Type
						if typ != nil {
							if ptr, ok := typ.(*types.Pointer); ok {
								typ = ptr.Elem()
							}
							if st, ok := typ.Underlying().(*types.Struct); ok {
								for i, elt := range lit.Elts {
									if kv, ok := elt.(*ast.KeyValueExpr); ok {
										if keyId, ok := kv.Key.(*ast.Ident); ok {
											var fieldVar *types.Var
											if fv, ok := info.Uses[keyId].(*types.Var); ok {
												fieldVar = fv
											} else {
												for j := 0; j < st.NumFields(); j++ {
													if st.Field(j).Name() == keyId.Name {
														fieldVar = st.Field(j)
														break
													}
												}
											}
											if fieldVar != nil {
												if _, isSig := fieldVar.Type().Underlying().(*types.Signature); isSig {
													for _, target := range extractTargetFuncs(info, encDecl, kv.Value, 0) {
														if addFunc(structFieldFuncs, structFieldKey(fieldVar, typ), target) {
															added++
														}
													}
												}
											}
										}
									} else if i < st.NumFields() {
										fieldVar := st.Field(i)
										if _, isSig := fieldVar.Type().Underlying().(*types.Signature); isSig {
											for _, target := range extractTargetFuncs(info, encDecl, elt, 0) {
												if addFunc(structFieldFuncs, structFieldKey(fieldVar, typ), target) {
													added++
												}
											}
										}
									}
								}
							}
						}
					}
					if assign, ok := n.(*ast.AssignStmt); ok {
						for i, lhs := range assign.Lhs {
							var rhs ast.Expr
							if i < len(assign.Rhs) {
								rhs = assign.Rhs[i]
							} else if len(assign.Rhs) == 1 {
								rhs = assign.Rhs[0]
							}
							if rhs == nil {
								continue
							}
							if sel, ok := lhs.(*ast.SelectorExpr); ok {
								if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
									if fieldVar, ok := selection.Obj().(*types.Var); ok {
										if _, isSig := fieldVar.Type().Underlying().(*types.Signature); isSig {
											for _, target := range extractTargetFuncs(info, encDecl, rhs, 0) {
												if addFunc(structFieldFuncs, structFieldKey(fieldVar, selection.Recv()), target) {
													added++
												}
											}
										}
									}
								} else if info.Selections[sel] == nil {
									obj := info.ObjectOf(sel.Sel)
									if v, ok := obj.(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
										if _, isSig := v.Type().Underlying().(*types.Signature); isSig {
											for _, target := range extractTargetFuncs(info, encDecl, rhs, 0) {
												if addFunc(pkgVarFuncs, pkgVarKey(v), target) {
													added++
												}
											}
										}
									}
								}
							} else if id, ok := lhs.(*ast.Ident); ok {
								obj := info.ObjectOf(id)
								if v, ok := obj.(*types.Var); ok && v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
									if _, isSig := v.Type().Underlying().(*types.Signature); isSig {
										for _, target := range extractTargetFuncs(info, encDecl, rhs, 0) {
											if addFunc(pkgVarFuncs, pkgVarKey(v), target) {
												added++
											}
										}
									}
								}
							}
						}
					}
					return true
				})
			}
		}
		if added == 0 {
			break
		}
	}

	for _, pkg := range pkgs {
		info := pkg.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range pkg.Syntax {
			var caller string
			var encDecl *ast.FuncDecl
			ast.Inspect(f, func(n ast.Node) bool {
				if fn, ok := n.(*ast.FuncDecl); ok && fn.Name != nil {
					caller = fn.Name.Name
					encDecl = fn
					if fn.Recv != nil && len(fn.Recv.List) > 0 {
						caller = recvDeclName(fn.Recv.List[0].Type) + "." + fn.Name.Name
					}
					return true
				}
				call, ok := n.(*ast.CallExpr)
				if !ok || caller == "" {
					return true
				}
				fun := call.Fun
				for {
					if p, ok := fun.(*ast.ParenExpr); ok {
						fun = p.X
						continue
					}
					break
				}
				obj := calleeObject(info, fun)
				handleCallee := func(fn *types.Func) bool {
					if fn == nil || fn.Pkg() == nil {
						return false
					}
					p := fn.Pkg().Path()
					if p != module && !strings.HasPrefix(p, module+"/") {
						return false
					}
					callee := p + "." + fn.Name()
					if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
						rt := sig.Recv().Type()
						callee = p + "." + recvTypeName(rt) + "." + fn.Name()
						// Interface dispatch: the callee is the interface
						// method — record the site so impl edges below can be
						// narrowed by the dispatch key.
						switch rt.Underlying().(type) {
						case *types.Interface:
							if named := ifaceNamed(rt); named != nil {
								if ifaceSites[named] == nil {
									ifaceSites[named] = map[string][]ifaceSite{}
								}
								ifaceSites[named][fn.Name()] = append(ifaceSites[named][fn.Name()], ifaceSite{pkg, encDecl, call})
							} else {
								// Anonymous/interface-literal receiver: the
								// call resolves to the interface method but
								// no impl edges are enumerable — the graph
								// is incomplete, not "no path".
								iface, _ := rt.Underlying().(*types.Interface)
								addOpaque(pkg.PkgPath+"."+caller, opaqueSite{iface: iface})
							}
						}
					}
					addEdge(pkg.PkgPath+"."+caller, callee)
					return true
				}
				if fn, ok := obj.(*types.Func); ok {
					if fn.Pkg() != nil {
						handleCallee(fn)
					}
					return true
				}
				if v, ok := obj.(*types.Var); ok {
					if _, isSig := v.Type().Underlying().(*types.Signature); isSig {
						// 1. Struct field func callback dispatch
						if sel, ok := fun.(*ast.SelectorExpr); ok {
							if selection, ok := info.Selections[sel]; ok && selection.Kind() == types.FieldVal {
								key := structFieldKey(v, selection.Recv())
								targets := structFieldFuncs[key]
								if len(targets) > 0 {
									allResolved := true
									for _, t := range targets {
										if t != nil && t.Pkg() != nil {
											handleCallee(t)
										} else {
											allResolved = false
										}
									}
									if allResolved {
										return true
									}
								}
								sig, _ := v.Type().Underlying().(*types.Signature)
								addOpaque(pkg.PkgPath+"."+caller, opaqueSite{sig: sig})
								return true
							}
						}
						// 2. Package-level function variable
						if v.Pkg() != nil && v.Parent() == v.Pkg().Scope() {
							key := pkgVarKey(v)
							targets := pkgVarFuncs[key]
							if len(targets) > 0 {
								allResolved := true
								for _, t := range targets {
									if t != nil && t.Pkg() != nil {
										handleCallee(t)
									} else {
										allResolved = false
									}
								}
								if allResolved {
									return true
								}
							}
							sig, _ := v.Type().Underlying().(*types.Signature)
							addOpaque(pkg.PkgPath+"."+caller, opaqueSite{sig: sig})
							return true
						}
						// 3. Local func variable / method value
						if encDecl != nil {
							rhss := assignRHS(info, encDecl, v)
							if len(rhss) > 0 {
								allResolved := true
								for _, r := range rhss {
									targets := extractTargetFuncs(info, encDecl, r.expr, 0)
									if len(targets) > 0 {
										for _, t := range targets {
											if t != nil && t.Pkg() != nil {
												handleCallee(t)
											} else {
												allResolved = false
											}
										}
									} else {
										allResolved = false
									}
								}
								if allResolved {
									return true
								}
							}
						}
					}
				}
				// Func values and map-indexed calls hide their target
				// from the chain — absence of a found chain is then
				// not evidence of absence. Builtins and type
				// conversions resolve to no *types.Func either, but
				// call nothing user-defined.
				switch obj.(type) {
				case *types.Builtin, *types.TypeName:
				default:
					if tv, ok := info.Types[fun]; ok && tv.IsType() {
						break
					}
					var siteSig *types.Signature
					if tv, ok := info.Types[fun]; ok && tv.Type != nil {
						if sig, ok := tv.Type.Underlying().(*types.Signature); ok {
							siteSig = sig
						}
					}
					if siteSig == nil {
						if v, ok := obj.(*types.Var); ok {
							if sig, ok := v.Type().Underlying().(*types.Signature); ok {
								siteSig = sig
							}
						}
					}
					addOpaque(pkg.PkgPath+"."+caller, opaqueSite{sig: siteSig})
				}
				return true
			})
		}
	}
	// Link interface methods to their concrete implementations declared in
	// the module — a registry call "Getter.Get" reaches every Getter impl.
	// Two narrowing layers keep the fan-out honest:
	//   - instantiation: a type never created in loaded code cannot be a
	//     dispatch target (test mocks, dead alternatives); skipped entirely
	//     under reflect.New/unsafe/plugin/linkname;
	//   - dispatch key: a site `g.M()` where g = registry[key] and key
	//     evaluates to constants reaches only the registered impls at
	//     those keys; an unevaluable site stays unrestricted — then all
	inst, narrowing := ix.instantiated()
	if narrowing {
		modInst, modDisabled := instantiatedNamed(pkgs)
		if modDisabled {
			narrowing = false
		} else {
			combined := make(map[string]bool, len(inst)+len(modInst))
			for k, v := range inst {
				combined[k] = v
			}
			for k, v := range modInst {
				combined[k] = v
			}
			inst = combined
		}
	}
	for named, methods := range ifaceSites {
		for method, sites := range methods {
			// Union of per-site allowed impls; any unrestricted site
			// widens the pair back to every impl.
			var allowed map[string]bool
			for _, s := range sites {
				set := ix.dispatchImpls(s.pkg, s.enc, s.call)
				if set == nil {
					allowed = nil
					break
				}
				if allowed == nil {
					allowed = map[string]bool{}
				}
				for name := range set {
					allowed[name] = true
				}
			}
			linked := 0
			for _, pkg := range pkgs {
				if pkg.Types == nil {
					continue
				}
				for _, name := range pkg.Types.Scope().Names() {
					if allowed != nil && !allowed[name] {
						continue
					}
					tn, ok := pkg.Types.Scope().Lookup(name).(*types.TypeName)
					if !ok {
						continue
					}
					t := tn.Type()
					implNamed, _ := t.(*types.Named)
					if narrowing && implNamed != nil && !inst[namedKey(implNamed)] {
						continue
					}
					iface, _ := named.Underlying().(*types.Interface)
					if iface == nil || !types.Implements(types.NewPointer(t), iface) {
						continue
					}
					ms := types.NewMethodSet(types.NewPointer(t))
					for i := 0; i < ms.Len(); i++ {
						m := ms.At(i).Obj()
						if m.Name() != method {
							continue
						}
						ifaceKey := named.Obj().Pkg().Path() + "." + named.Obj().Name() + "." + method
						implKey := m.Pkg().Path() + "." + name + "." + method
						addEdge(ifaceKey, implKey)
						linked++
					}
				}
			}
			if linked == 0 {
				// A live interface call whose impls are invisible to the
				// loaded graph (invisible instantiation, unloaded impl
				// package) leaves the callee unreached — that is unknown
				// reachability, not disproven.
				iface, _ := named.Underlying().(*types.Interface)
				for _, s := range sites {
					if s.enc != nil && s.enc.Name != nil {
						fnName := s.enc.Name.Name
						if s.enc.Recv != nil && len(s.enc.Recv.List) > 0 {
							fnName = recvDeclName(s.enc.Recv.List[0].Type) + "." + fnName
						}
						addOpaque(s.pkg.PkgPath+"."+fnName, opaqueSite{iface: iface})
					}
				}
			}
		}
	}
	return edges, opaqueSites
}

// namedKey canonicalizes a named type across load instances — the same
// dependency type materializes once through the product's import data
// and once through the source-loaded dep package; pointer identity does
// not survive that split, so the key is the declaring package path and
// name.
func namedKey(n *types.Named) string {
	if n == nil || n.Obj() == nil || n.Obj().Pkg() == nil {
		return ""
	}
	return n.Obj().Pkg().Path() + "." + n.Obj().Name()
}

// instantiatedNamed collects named types concretely created by the
// packages' syntax: composite literals, new(T), var declarations with an
// explicit type, make() and type conversions. The set is expanded over
// struct fields and container element types — `&Wrapper{}` also creates
// its field values. disabled is true when syntax can materialize values
// invisibly (reflect.New/NewAt, unsafe, plugin, go:linkname): then the
// set is incomplete and must not narrow dispatch.
func instantiatedNamed(pkgs []*packages.Package) (set map[string]bool, disabled bool) {
	set = map[string]bool{}
	var add func(t types.Type)
	add = func(t types.Type) {
		if t == nil {
			return
		}
		if tup, ok := t.(*types.Tuple); ok {
			for i := 0; i < tup.Len(); i++ {
				add(tup.At(i).Type())
			}
			return
		}
		for {
			if p, ok := t.(*types.Pointer); ok {
				t = p.Elem()
				continue
			}
			break
		}
		if s, ok := t.(*types.Slice); ok {
			add(s.Elem())
			return
		}
		if a, ok := t.(*types.Array); ok {
			add(a.Elem())
			return
		}
		if m, ok := t.(*types.Map); ok {
			add(m.Key())
			add(m.Elem())
			return
		}
		if c, ok := t.(*types.Chan); ok {
			add(c.Elem())
			return
		}
		n, ok := t.(*types.Named)
		if !ok || n.Underlying() == nil {
			return
		}
		if _, ok := n.Underlying().(*types.Interface); ok {
			return
		}
		key := namedKey(n)
		if key == "" || set[key] {
			return
		}
		set[key] = true
		// Instantiating a named type creates its contained values too:
		// struct fields (incl. embedded), slice/array/map/channel elems.
		switch u := n.Underlying().(type) {
		case *types.Struct:
			for i := 0; i < u.NumFields(); i++ {
				add(u.Field(i).Type())
			}
		case *types.Slice:
			add(u.Elem())
		case *types.Array:
			add(u.Elem())
		case *types.Map:
			add(u.Elem())
			add(u.Key())
		case *types.Chan:
			add(u.Elem())
		}
	}
	for _, pkg := range pkgs {
		info := pkg.TypesInfo
		for _, f := range pkg.Syntax {
			for _, imp := range f.Imports {
				switch strings.Trim(imp.Path.Value, `"`) {
				case "unsafe", "plugin":
					disabled = true
				}
			}
			ast.Inspect(f, func(n ast.Node) bool {
				switch e := n.(type) {
				case *ast.CompositeLit:
					if info != nil {
						add(info.TypeOf(e.Type))
					}
				case *ast.ValueSpec:
					if info != nil && e.Type != nil {
						add(info.TypeOf(e.Type))
					}
				case *ast.CallExpr:
					if info != nil {
						add(info.TypeOf(e))
					}
					obj := calleeObject(info, e.Fun)
					switch o := obj.(type) {
					case *types.Builtin:
						if o.Name() == "new" && len(e.Args) == 1 && info != nil {
							add(info.TypeOf(e.Args[0]))
						}
						if o.Name() == "make" && len(e.Args) >= 1 && info != nil {
							add(info.TypeOf(e.Args[0]))
						}
					case *types.TypeName:
						// T(x) conversion — counts as instantiation; a
						// rare T(nil) over-marks, which is the safe side.
						if nt, ok := o.Type().(*types.Named); ok {
							add(nt)
						}
					case *types.Func:
						if o.Pkg() != nil && o.Pkg().Path() == "reflect" &&
							(o.Name() == "New" || o.Name() == "NewAt") {
							disabled = true
						}
					}
				}
				return true
			})
			for _, cg := range f.Comments {
				for _, cm := range cg.List {
					if strings.HasPrefix(cm.Text, "//go:linkname") {
						disabled = true
					}
				}
			}
		}
	}
	return set, disabled
}

// instantiated returns the memoized instantiation set over all loaded
// packages (product + extras); narrow=false when dynamic materialization
// was seen and the set must not restrict dispatch.
func (ix *Index) instantiated() (map[string]bool, bool) {
	if ix.instSet != nil && ix.instGen == ix.extrasGen {
		return ix.instSet, !ix.instDisabled
	}
	pkgs := append(append([]*packages.Package{}, ix.allExtras()...), ix.pkgs...)
	set, disabled := instantiatedNamed(pkgs)
	ix.instSet, ix.instDisabled, ix.instGen = set, disabled, ix.extrasGen
	return set, !disabled
}

// IsReceiverTypeInstantiated reports whether the receiver type of ref (if ref
// is a method) is known to be instantiated in the analyzed code.
// Standalone functions (no receiver type) conservatively return true.
func (ix *Index) IsReceiverTypeInstantiated(ref domain.SymbolRef) bool {
	if ix == nil {
		return true
	}
	typeName, _ := splitSymbol(ref.Symbol)
	typeName = strings.TrimSpace(typeName)
	typeName = strings.Trim(typeName, "()*")
	typeName = strings.TrimSpace(typeName)
	if typeName == "" {
		return true
	}
	ix.mu.Lock()
	defer ix.mu.Unlock()
	if err := ix.load(ix.ctxOr(nil)); err != nil {
		return true
	}
	inst, _ := ix.instantiated()
	if inst == nil {
		return true
	}
	key := ref.Package + "." + typeName
	return inst[key]
}

// depCone returns the set of module functions reachable from the product's
// call sites into the module — the entry cone. Dep-internal callers inside
// this cone can carry product-supplied data; callers outside it are
// alternative module flows (mocks, other getters, meta machinery) that the
// product never drives — merging their origins over-approximates toward
// EXTERNAL_UNTRUSTED and can never disprove exploitability.
func (ix *Index) depCone(module string) map[string]bool {
	if c, ok := ix.coneCache[module]; ok {
		return c
	}
	if ix.coneBusy == nil {
		ix.coneBusy = map[string]bool{}
	}
	if ix.coneBusy[module] {
		// Cone under construction — dispatch narrowing inside edge
		// building asks back through siteOnPath; answer permissively
		// so the graph stays over-approximate rather than recursive.
		return nil
	}
	ix.coneBusy[module] = true
	defer delete(ix.coneBusy, module)
	pkgs, err := ix.loadExtra(ix.ctxOr(nil), module+"/...")
	if err != nil {
		return nil
	}
	edges, opaqueCallers := ix.moduleEdges(pkgs, module)
	// Seed with every product call site whose callee lands in the module —
	// the same callee-key format moduleEdges produces.
	entries := map[string]bool{}
	for _, p := range ix.pkgs {
		info := p.TypesInfo
		if info == nil {
			continue
		}
		for _, f := range p.Syntax {
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				fn, ok := calleeObject(info, call.Fun).(*types.Func)
				if !ok || fn.Pkg() == nil {
					return true
				}
				fp := fn.Pkg().Path()
				if fp != module && !strings.HasPrefix(fp, module+"/") {
					return true
				}
				callee := fp + "." + fn.Name()
				if sig, ok := fn.Type().(*types.Signature); ok && sig.Recv() != nil {
					callee = fp + "." + recvTypeName(sig.Recv().Type()) + "." + fn.Name()
				}
				entries[callee] = true
				return true
			})
		}
	}
	cone := map[string]bool{}
	var stack []string
	for e := range entries {
		if !cone[e] {
			cone[e] = true
			stack = append(stack, e)
		}
	}
	for len(stack) > 0 {
		k := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for next := range edges[k] {
			if !cone[next] {
				cone[next] = true
				stack = append(stack, next)
			}
		}
	}
	for c := range cone {
		if opaqueCallers[c] {
			if ix.coneCache == nil {
				ix.coneCache = map[string]map[string]bool{}
			}
			ix.coneCache[module] = nil
			return nil
		}
	}
	if ix.coneCache == nil {
		ix.coneCache = map[string]map[string]bool{}
	}
	ix.coneCache[module] = cone
	return cone
}

// callerOnPath reports whether a caller site can carry product-supplied
// data: product callers always qualify; dep-internal callers qualify only
// when their enclosing function lies in the module's entry cone. Data
// needed to decide stays unknown-biased: when the module or cone cannot
// be computed the caller is kept.
func (ix *Index) callerOnPath(r CallSiteRef) bool {
	return ix.siteOnPath(r.pkg, r.enclosing)
}

// siteOnPath is the shared product-driven-cone check: product code and
// package-level declarations always qualify; a dep-internal site qualifies
// only when its enclosing function lies in the module's entry cone. When
// module/cone cannot be computed the site is kept — unknown-biased.
func (ix *Index) siteOnPath(pkg *packages.Package, enc *ast.FuncDecl) bool {
	if pkg == nil || enc == nil || ix.isProductPath(pkg.PkgPath) {
		return true
	}
	mod := ""
	if pkg.Module != nil {
		mod = pkg.Module.Path
	}
	if mod == "" {
		return true
	}
	cone := ix.depCone(mod)
	if cone == nil {
		return true
	}
	caller := enc.Name.Name
	if enc.Recv != nil && len(enc.Recv.List) > 0 {
		caller = recvDeclName(enc.Recv.List[0].Type) + "." + caller
	}
	// init runs unconditionally at package load — it is on every path
	// even though no caller ever names it.
	if caller == "init" {
		return true
	}
	return cone[pkg.PkgPath+"."+caller]
}

// ifaceNamed returns the named interface type of a receiver, or nil when
// the receiver is a concrete type (methods on concrete receivers are
// ordinary direct calls for reachability purposes).
func ifaceNamed(t types.Type) *types.Named {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return nil
	}
	if _, isIface := named.Underlying().(*types.Interface); !isIface {
		return nil
	}
	return named
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
				if as, ok := n.(*ast.AssignStmt); ok {
					for _, lhs := range as.Lhs {
						// A store through an unsafe.Pointer-derived deref —
						// `*(*T)(unsafe.Pointer(&x)) = v` or an index-assign
						// into an unsafe.Slice — can write any field (even
						// unexported) out of sight of syntactic write-site
						// scans. The bare `unsafe` import cannot write
						// anything by itself.
						var target ast.Expr
						switch l := lhs.(type) {
						case *ast.StarExpr:
							target = l.X
						case *ast.IndexExpr:
							target = l
						}
						if target != nil && callsUnsafe(pkg.TypesInfo, target) {
							out = append(out, DynamicMarker{
								CallSite: pos(as), Kind: "unsafe_write",
								Detail: "store through unsafe.Pointer-derived value can write fields invisibly",
							})
						}
					}
				}
				if call, ok := n.(*ast.CallExpr); ok {
					callFuns[call.Fun] = true
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						callFuns[sel.Sel] = true
						// A materialized unsafe.Pointer (Pointer conversion
						// or unsafe.Add) can be stored anywhere and written
						// through later — its aliased uses are untraceable
						// cheaply, so its mere presence weakens field-write
						// coverage.
						if (sel.Sel.Name == "Pointer" || sel.Sel.Name == "Add") &&
							isUnsafePkg(pkg.TypesInfo, sel.X) {
							out = append(out, DynamicMarker{
								CallSite: pos(call), Kind: "unsafe_ptr",
								Detail: "unsafe." + sel.Sel.Name + " materializes a raw pointer; aliased writes are untraceable",
							})
						}
						// reflect.Value.Set* mutates the underlying value —
						// the only reflect shape that can write a guarded
						// field/variable. The bare `reflect` import or
						// read-only calls (TypeOf, DeepEqual, Interface)
						// cannot.
						if strings.HasPrefix(sel.Sel.Name, "Set") &&
							isReflectValue(pkg.TypesInfo, sel.X) {
							out = append(out, DynamicMarker{
								CallSite: pos(call), Kind: "reflect_write",
								Detail: "reflect.Value." + sel.Sel.Name + " call can write fields invisibly",
							})
						}
						// reflect.Value.MethodByName / Method can invoke methods
						// dynamically — the only reflect shape that can widen the call graph.
						if (sel.Sel.Name == "MethodByName" || sel.Sel.Name == "Method") &&
							isReflectValueOrType(pkg.TypesInfo, sel.X) {
							out = append(out, DynamicMarker{
								CallSite: pos(call), Kind: "reflect_method",
								Detail: "reflect." + sel.Sel.Name + " call can invoke methods dynamically",
							})
						}
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

// isReflectValue reports whether e's static type is reflect.Value — the
// receiver shape of the mutating Set* calls.
func isReflectValue(info *types.Info, e ast.Expr) bool {
	if info == nil {
		return false
	}
	t := info.TypeOf(e)
	if t == nil {
		return false
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Pkg().Path() == "reflect" && n.Obj().Name() == "Value"
}

func isReflectValueOrType(info *types.Info, e ast.Expr) bool {
	if info == nil {
		return false
	}
	t := info.TypeOf(e)
	if t == nil {
		return false
	}
	// For interface types like reflect.Type:
	if iface, ok := t.Underlying().(*types.Interface); ok {
		if n, ok := t.(*types.Named); ok && n.Obj() != nil && n.Obj().Pkg() != nil {
			if n.Obj().Pkg().Path() == "reflect" && n.Obj().Name() == "Type" {
				return true
			}
		}
		_ = iface
	}
	n, ok := t.(*types.Named)
	if !ok || n.Obj() == nil || n.Obj().Pkg() == nil {
		return false
	}
	return n.Obj().Pkg().Path() == "reflect" && (n.Obj().Name() == "Value" || n.Obj().Name() == "Type")
}

// callsUnsafe reports whether e contains a call to a function from the
// unsafe package — unsafe.Pointer, unsafe.Add, unsafe.Slice and friends.
func callsUnsafe(info *types.Info, e ast.Expr) bool {
	if info == nil {
		return false
	}
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if found {
			return false
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && isUnsafePkg(info, sel.X) {
			found = true
			return false
		}
		return true
	})
	return found
}

// isUnsafePkg reports whether e is a qualifier ident resolving to the
// unsafe package.
func isUnsafePkg(info *types.Info, e ast.Expr) bool {
	if info == nil {
		return false
	}
	id, ok := e.(*ast.Ident)
	if !ok {
		return false
	}
	pn, ok := info.ObjectOf(id).(*types.PkgName)
	return ok && pn.Imported().Path() == "unsafe"
}
