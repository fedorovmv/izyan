package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Receiver-binding union: an iface call whose receiver is bound by more
// than one map lookup must keep impls of EVERY binding — a re-picked
// assignment does not erase what the first lookup can still produce
// (`r := registry["vulnerable"]; if flag { r = registry["safe"] }`).
func TestDispatchReceiverUnion(t *testing.T) {
	ix := fixture(t, "eitherprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	cone := ix.depCone("example.com/dep2")
	if cone == nil {
		t.Fatal("depCone nil — module load failed or graph marked opaque")
	}
	if !cone["example.com/dep2/vuln.RealRunner.Run"] {
		t.Fatal("RealRunner.Run missing — first binding's impl dropped by last-write narrowing")
	}
	if !cone["example.com/dep2/vuln.SafeRunner.Run"] {
		t.Fatal("SafeRunner.Run missing — re-picked binding's impl lost")
	}
}

// Index-mutated registry: literal content is not the complete table, so
// dispatch narrowing must not restrict the site — impls registered at
// runtime remain reachable.
func TestDispatchMutatedMapUnrestricted(t *testing.T) {
	ix := fixture(t, "lateprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	cone := ix.depCone("example.com/dep3")
	if cone == nil {
		t.Fatal("depCone nil — module load failed or graph marked opaque")
	}
	if !cone["example.com/dep3/vuln.RealRunner.Run"] {
		t.Fatal("RealRunner.Run missing — runtime-registered impl dropped by literal-table narrowing")
	}
	if !cone["example.com/dep3/vuln.SafeRunner.Run"] {
		t.Fatal("SafeRunner.Run missing")
	}
}

// Aliased mutation (`a := runners; a["k"] = impl`) writes the registry
// without naming it — completeness tracking that watches only the
// declared variable would keep a narrowed table and drop impls the
// runtime write can introduce.
func TestDispatchAliasMutationUnrestricted(t *testing.T) {
	ix := fixture(t, "aliasprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	cone := ix.depCone("example.com/dep4")
	if cone == nil {
		t.Fatal("depCone nil — module load failed or graph marked opaque")
	}
	if !cone["example.com/dep4/vuln.ExtraRunner.Run"] {
		t.Fatal("ExtraRunner.Run missing — alias write must invalidate the literal-table narrowing")
	}
}

// A product write into the dependency's exported registry mutates the
// table from a different packages.Load graph — object identity must be
// by Object.Id, or the narrowing keeps a table the product just changed.
func TestDispatchProductSideMutationUnrestricted(t *testing.T) {
	ix := fixture(t, "regmutprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	cone := ix.depCone("example.com/dep6")
	if cone == nil {
		t.Fatal("depCone nil — module load failed or graph marked opaque")
	}
	if !cone["example.com/dep6/vuln.ExtraRunner.Run"] {
		t.Fatal("ExtraRunner.Run missing — product-side registry write must invalidate narrowing")
	}
}

// Opaque dep graphs must not feed the cone filter: func-value calls and
// anonymous-interface dispatch make the edge set incomplete, and a nil
// (unrestricted) cone is the fail-open answer — never a proven absence
// that lets provenance drop off-cone call sites.
func TestDepConeOpaqueIsUnrestricted(t *testing.T) {
	ix := fixture(t, "dynprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cone := ix.depCone("example.com/dyndep"); cone != nil {
		t.Fatalf("opaque module produced a restricting cone: %v", cone)
	}
}

func TestModuleInternalReachOpaqueScoping(t *testing.T) {
	ix := fixture(t, "dynprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Case 1: Entry calls RunWith, which contains a func-value call.
	// Opaque must be true because opaque dispatch is reachable from entry.
	_, opaque1, err := ix.ModuleInternalReach(context.Background(), "example.com/dyndep", []string{"example.com/dyndep/dyn.RunWith"}, []domain.SymbolRef{{Package: "example.com/dyndep/dyn", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if !opaque1 {
		t.Fatal("expected opaque=true when entry calls function with func-value dispatch")
	}

	// Case 2: Entry calls Vulnerable, which is isolated from RunWith and AnonRunner.
	// Opaque must be false because the opaque callers are not reachable from Vulnerable.
	_, opaque2, err := ix.ModuleInternalReach(context.Background(), "example.com/dyndep", []string{"example.com/dyndep/dyn.Vulnerable"}, []domain.SymbolRef{{Package: "example.com/dyndep/dyn", Symbol: "Vulnerable"}})
	if err != nil {
		t.Fatal(err)
	}
	if opaque2 {
		t.Fatal("expected opaque=false when entry does not reach any opaque callers")
	}
}

// Integration test on real-micro-xds verifying full static reachability from
// xds gRPC server entrypoints to the RBAC filter parser without opaque degradation.
func TestModuleInternalReach_XDS(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "eval", ".gen", "real-micro-xds"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Skip("skipping integration test: eval/.gen/real-micro-xds not generated")
	}

	ix := &Index{Dir: dir}
	entries := []string{
		"google.golang.org/grpc/xds.NewGRPCServer",
		"google.golang.org/grpc/xds.GRPCServer.Serve",
	}
	subjects := []domain.SymbolRef{
		{
			Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac",
			Symbol:  "builder.ParseFilterConfig",
		},
		{
			Package: "google.golang.org/grpc/internal/xds/httpfilter/rbac",
			Symbol:  "parseConfig",
		},
	}

	reach, _, err := ix.ModuleInternalReach(context.Background(), "google.golang.org/grpc", entries, subjects)
	if err != nil {
		t.Fatalf("ModuleInternalReach failed: %v", err)
	}

	chain := reach["google.golang.org/grpc/internal/xds/httpfilter/rbac.parseConfig"]
	if len(chain) < 15 {
		t.Fatalf("reach chain for parseConfig len = %d, want >= 15; chain: %v", len(chain), chain)
	}
	if reach["google.golang.org/grpc/internal/xds/httpfilter/rbac.builder.ParseFilterConfig"] == nil {
		t.Fatalf("reach chain for builder.ParseFilterConfig missing; reach: %v", reach)
	}
}
