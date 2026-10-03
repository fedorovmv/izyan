package goanalysis

import (
	"context"
	"fmt"
	"go/ast"
	"go/types"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

// SinkClosure enumerates every call site of each subject in the
// completeness-declared sink set — product packages plus the reachable
// dependency cone — and classifies the payload input at each site that
// can execute in the effective build. argIndex selects the payload
// argument; a negative value covers every argument plus the receiver of
// the call (a method's receiver state is itself a payload position).
//
// A site is dead only with positive unreachable evidence — an unlinked
// package, a caller with no resolvable invocation path, or a method
// reachable solely through a reflect-dispatched API whose call sites
// cannot carry its receiver type (callerReachable). Dead sites are
// recorded for audit but contribute nothing. Everything else —
// unresolvable provenance, unseen callers, undischarged dispatch —
// keeps the closure incomplete rather than guessed safe.
//
// Complete requires: the recorded basis (a sink-set completeness
// contract), zero enumeration blockers, and every live site's payload
// input resolved to a non-external origin.
func (ix *Index) SinkClosure(ctx context.Context, condID domain.ConditionID, module, basis string,
	subjects []domain.SymbolRef, argIndex, hops int) (domain.SinkClosure, []domain.Evidence, error) {

	ix.mu.Lock()
	defer ix.mu.Unlock()
	ctx = ix.ctxOr(ctx)
	if err := ix.load(ctx); err != nil {
		return domain.SinkClosure{}, nil, err
	}
	cl := domain.SinkClosure{ConditionID: condID, Module: module, Basis: basis}
	if basis == "" {
		cl.Blockers = append(cl.Blockers,
			"sink set has no completeness contract (KNOWN_ONLY)")
	}
	if len(subjects) == 0 {
		cl.Blockers = append(cl.Blockers, "empty sink set")
	}
	prev := ix.hopLimit
	ix.hopLimit = hops
	ix.funcDeclCache = map[string]funcDeclResult{}
	defer func() {
		ix.hopLimit = prev
		ix.funcDeclCache = nil
	}()
	var livePos, dead, unsafePos, unresolved int
	pinned := map[string]bool{}
	for _, subj := range subjects {
		key := subj.Package + "." + subj.Symbol
		// Every declared sink must exist in the analyzed version — a
		// missing symbol leaves the set's coverage unproven.
		cs, err := ix.findSymbol(ctx, subj)
		if err != nil || cs == nil {
			cl.Blockers = append(cl.Blockers,
				fmt.Sprintf("declared sink %s not found in analyzed version", key))
			continue
		}
		spkg := ix.pkgForPath(subj.Package)
		if spkg == nil {
			cl.Blockers = append(cl.Blockers,
				fmt.Sprintf("declared sink %s: owning package not loaded", key))
			continue
		}
		// Whole-module load so module-internal callers are enumerable —
		// callerScope for dep packages covers product+extras, and the
		// extras must include every package of the subject's module.
		if spkg.Module != nil {
			pattern := spkg.Module.Path + "/..."
			if _, err := ix.loadExtra(ctx, pattern); err != nil {
				cl.Blockers = append(cl.Blockers,
					fmt.Sprintf("declared sink %s: module load failed: %v", key, err))
			} else {
				// The subject module stays resident through the closure —
				// evicting it mid-verification drops its callers and turns
				// resolved payload positions UNKNOWN.
				if !pinned[pattern] {
					defer ix.pinExtraScoped(pattern)()
					pinned[pattern] = true
				}
			}
		}
		cl.Blockers = append(cl.Blockers, ix.unseenDepCallers(ctx, subj, spkg)...)
		seen := map[string]bool{}
		for _, r := range ix.callersOf(spkg, subj) {
			if r.possible {
				cl.Blockers = append(cl.Blockers, fmt.Sprintf(
					"declared sink %s: caller set changed or has unresolved function-value dispatch", key))
				if r.call == nil || r.pkg == nil {
					continue
				}
			}
			skey := fmt.Sprintf("%s:%d:%d", r.Site.File, r.Site.Line, r.Site.Column)
			if seen[skey] {
				continue
			}
			seen[skey] = true
			if !ix.callerReachable(r.pkg, r.enclosing) {
				dead++
				cl.Sites = append(cl.Sites, domain.SinkSite{
					CallSite: r.Site, Sink: key, Arg: -1, Live: false,
					Detail: "dead in effective build",
				})
				continue
			}
			call := r.call
			var positions []struct {
				arg  int
				expr ast.Expr
			}
			add := func(arg int, e ast.Expr) {
				positions = append(positions, struct {
					arg  int
					expr ast.Expr
				}{arg, e})
			}
			if argIndex >= 0 {
				if argIndex < len(call.Args) {
					add(argIndex, call.Args[argIndex])
				}
			} else {
				for i, a := range call.Args {
					add(i, a)
				}
			}
			// The receiver of a method call is object state the callee
			// reads — a payload position in its own right (a decoder's
			// buffer never travels through an argument).
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if selection := r.pkg.TypesInfo.Selections[sel]; selection != nil && selection.Kind() == types.MethodVal {
					add(-1, sel.X)
				}
			}
			for _, p := range positions {
				var tx []domain.CallSite
				ix.txBuf = &tx
				ix.traceSeen = map[types.Object]bool{}
				ix.paramSeen = map[string]bool{}
				ix.paramCache = map[string]classifyResult{}
				ix.classifyCache = map[classifyKey]classifyResult{}
				// Per-position budget: protojson-scale receivers trace
				// through whole decoder bodies — 300k evals is too shallow;
				// exhaustion stays UNKNOWN rather than risking unbounded
				// fan-out (aws-scale cones made the case hang).
				ix.evalBudget = maxEvalBudget * 4
				origin, why := ix.classify(r.pkg, r.enclosing, p.expr, 1)
				ix.txBuf = nil
				ix.txSeen = nil
				ix.traceSeen = nil
				ix.paramSeen = nil
				ix.paramCache = nil
				ix.classifyCache = nil
				ix.evalBudget = 0
				livePos++
				switch {
				case domain.SafeOrigin(origin):
				case origin == domain.OriginUnknown || origin == "":
					unresolved++
				default:
					unsafePos++
				}
				detail := why
				if len(detail) > 300 {
					detail = detail[:300]
				}
				cl.Sites = append(cl.Sites, domain.SinkSite{
					CallSite: r.Site, Sink: key, Arg: p.arg, Live: true,
					Origin: origin, Detail: detail,
				})
			}
		}
	}
	cl.Complete = len(cl.Blockers) == 0 && unsafePos == 0 && unresolved == 0
	return cl, []domain.Evidence{{
		Kind:    domain.EvidenceDataFlow,
		Quality: domain.QualityDeterministic,
		Source:  "dependency sink-closure inventory " + module,
		Tool:    "goanalysis.Index.SinkClosure",
		Content: fmt.Sprintf(
			"cond=%s sinks=%d live-positions=%d unsafe=%d unresolved=%d dead-sites=%d blockers=%d complete=%v",
			condID, len(subjects), livePos, unsafePos, unresolved, dead,
			len(cl.Blockers), cl.Complete),
	}}, nil
}

// pkgForPath locates a package among the loaded product roots and dep
// extras by its import path.
func (ix *Index) pkgForPath(path string) *packages.Package {
	for _, p := range ix.pkgs {
		if p.PkgPath == path {
			return p
		}
	}
	for _, p := range ix.allExtras() {
		if p.PkgPath == path {
			return p
		}
	}
	return nil
}

// unseenDepCallers reports dependency packages that import subj's
// package, can execute in this build, and are outside the loaded cone —
// the site enumeration cannot see their call sites, so each one blocks
// completeness. Product packages, same-module packages and loaded
// extras are covered; unlinked packages cannot execute.
func (ix *Index) unseenDepCallers(ctx context.Context, subj domain.SymbolRef, spkg *packages.Package) []string {
	mod := ""
	if spkg.Module != nil {
		mod = spkg.Module.Path
	}
	imps, err := ix.depImporters(ctx)
	if err != nil {
		return []string{fmt.Sprintf("dep-import index for %s unavailable: %v", subj.Package, err)}
	}
	linked := ix.linkedPaths()
	var out []string
	for _, imp := range imps[subj.Package] {
		if imp.path == subj.Package || (mod != "" && imp.module == mod) {
			continue // same package/module — covered by the module load
		}
		if ix.isProductPath(imp.path) {
			continue // product package — sites come from the root scan
		}
		if !linked[imp.path] {
			continue // unlinked — cannot execute in this build
		}
		if len(ix.extrasFor(imp.path)) > 0 {
			continue // loaded — sites enumerated
		}
		// The importer can execute but is not in the cone yet — pull it
		// in rather than give up on enumeration.
		if _, err := ix.loadExtra(ctx, imp.path); err == nil && len(ix.extrasFor(imp.path)) > 0 {
			continue
		}
		out = append(out, fmt.Sprintf(
			"dep package %s imports %s but is outside the enumerated cone — its call sites are unseen",
			imp.path, subj.Package))
	}
	return out
}
