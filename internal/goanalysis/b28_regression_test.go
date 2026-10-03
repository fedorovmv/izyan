package goanalysis

import (
	"context"
	"go/types"
	"strings"
	"testing"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

func TestSinkClosureHonorsContextDeadline(t *testing.T) {
	ix := fixture(t, "constprod")
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond) // ensure deadline exceeded

	cl, _, err := ix.SinkClosure(ctx, "C-INPUT", "example.com/dep", "explicit test basis",
		[]domain.SymbolRef{vulnSym}, 0, 16)
	if err != nil && !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("unexpected error: %v", err)
	}
	if cl.Complete {
		t.Fatal("SinkClosure must not report Complete=true when context deadline is exceeded")
	}
	hasDeadlineBlocker := false
	for _, b := range cl.Blockers {
		if strings.Contains(b, "deadline") || strings.Contains(b, "context") {
			hasDeadlineBlocker = true
			break
		}
	}
	if !hasDeadlineBlocker && err == nil {
		t.Fatalf("expected deadline blocker in cl.Blockers, got: %v", cl.Blockers)
	}
}

func TestSinkClosurePreloadedHonorsDeadline(t *testing.T) {
	ix := fixture(t, "constprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)

	cl, _, err := ix.SinkClosure(ctx, "C-INPUT", "example.com/dep", "explicit test basis",
		[]domain.SymbolRef{vulnSym}, 0, 16)
	if err != nil && !strings.Contains(err.Error(), "context") && !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("unexpected error: %v", err)
	}
	if cl.Complete {
		t.Fatal("SinkClosure must not report Complete=true when deadline exceeded")
	}
	hasBlocker := false
	for _, b := range cl.Blockers {
		if strings.Contains(b, "deadline") || strings.Contains(b, "context") {
			hasBlocker = true
			break
		}
	}
	if !hasBlocker && err == nil {
		t.Fatalf("expected deadline blocker, got: %v", cl.Blockers)
	}
}

func TestSinkClosurePackageLoadBudget(t *testing.T) {
	ix := fixture(t, "constprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ix.loadBudget = 1 // only 1 package load allowed
	cl, _, _ := ix.SinkClosure(context.Background(), "C-INPUT", "example.com/dep", "explicit test basis",
		[]domain.SymbolRef{vulnSym}, 0, 16)
	if cl.Complete {
		t.Fatal("SinkClosure must not report Complete=true when load budget is exhausted")
	}
	hasBlocker := false
	for _, b := range cl.Blockers {
		if strings.Contains(b, "budget") || strings.Contains(b, "load") {
			hasBlocker = true
			break
		}
	}
	if !hasBlocker {
		t.Fatalf("expected load budget blocker, got: %v", cl.Blockers)
	}
}

func TestPinExtraAllowsModulesUpToMaxPinned(t *testing.T) {
	// A standard module like golang.org/x/crypto has ~58 packages.
	// maxPinnedPkgs (128) must allow pinning patterns larger than maxExtraPkgs (96).
	const testPkgCount = 58
	pkgs := make([]*packages.Package, testPkgCount)
	for i := range pkgs {
		pkgs[i] = &packages.Package{PkgPath: "example.com/mod/pkg"}
	}
	ix := &Index{
		extraPkgs: map[string][]*packages.Package{
			"example.com/mod/...": pkgs,
		},
		extraOrder:  []string{"example.com/mod/..."},
		extraWeight: map[string]int{"example.com/mod/...": 100},
	}
	ix.pinExtra("example.com/mod/...")
	if !ix.extraPinned["example.com/mod/..."] {
		t.Fatalf("pinExtra failed to pin pattern with %d packages", testPkgCount)
	}

	// Verify evictExtra does not evict the pinned module when a small unpinned package is loaded.
	ix.extraPkgs["unpinned"] = []*packages.Package{{PkgPath: "unpinned"}}
	ix.extraOrder = append(ix.extraOrder, "unpinned")
	ix.extraWeight["unpinned"] = 10
	ix.evictExtra()

	if _, ok := ix.extraPkgs["example.com/mod/..."]; !ok {
		t.Fatal("evictExtra evicted the pinned module!")
	}
	if _, ok := ix.extraPkgs["unpinned"]; !ok {
		t.Fatal("evictExtra prematurely evicted the unpinned package despite unpinned budget being within limits")
	}
}

func TestPkgOfPathDoesNotLoadMidFvBuild(t *testing.T) {
	ix := &Index{
		fvBuildDepth: 1, // mid-build of func-value index
	}
	vr := types.NewVar(0, types.NewPackage("example.com/unloaded", "unloaded"), "someVar", types.Typ[types.Int])
	pkg := ix.pkgOfPath(vr)
	if pkg != nil {
		t.Fatalf("pkgOfPath must return nil when fvBuildDepth > 0, got %v", pkg)
	}
}
