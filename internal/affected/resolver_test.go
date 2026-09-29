package affected

import (
	"context"
	"errors"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

type fakeTool struct {
	modules  []byte
	packages []byte
	modErr   error
	pkgErr   error
}

func (f fakeTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, string, error) {
	return f.modules, "go list -m -json all", f.modErr
}

func (f fakeTool) ListPackages(context.Context, string, domain.ProductSnapshot) ([]byte, error) {
	return f.packages, f.pkgErr
}

var testVuln = domain.Vulnerability{
	ID:     "GO-0000-0001",
	Module: "example.com/dep",
	AffectedVersions: []domain.VersionRange{
		{Introduced: "0", Fixed: "1.2.0"},
	},
	AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
}

func product() domain.ProductSnapshot {
	return domain.ProductSnapshot{Repository: "/repo", Commit: "deadbeef", GOOS: "linux", GOARCH: "amd64"}
}

func resolve(t *testing.T, tool GoTool) domain.AffectedResult {
	t.Helper()
	res, _, err := GoResolver{Tool: tool}.Resolve(context.Background(), testVuln, product())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return res
}

func TestModuleAbsent(t *testing.T) {
	res := resolve(t, fakeTool{modules: []byte(`{"Path":"example.com/product","Main":true}`)})
	if res.ModulePresent != domain.ClaimFalse || res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("got %+v, want module/version FALSE", res)
	}
}

func TestVersionOutsideRange(t *testing.T) {
	mods := `{"Path":"example.com/product","Main":true}
{"Path":"example.com/dep","Version":"v1.2.0"}`
	res := resolve(t, fakeTool{modules: []byte(mods)})
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("v1.2.0 is the fixed version, got VersionAffected=%s", res.VersionAffected)
	}
	if res.ResolvedVersion != "v1.2.0" {
		t.Fatalf("resolved=%q", res.ResolvedVersion)
	}
}

func TestVersionInRangePackagePresent(t *testing.T) {
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/dep/vuln","Module":{"Path":"example.com/dep","Version":"v1.0.0"}}`
	res := resolve(t, fakeTool{modules: []byte(mods), packages: []byte(pkgs)})
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("got VersionAffected=%s", res.VersionAffected)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("got PackagePresent=%s", res.PackagePresent)
	}
}

func TestVersionInRangePackageAbsent(t *testing.T) {
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res := resolve(t, fakeTool{modules: []byte(mods), packages: []byte(pkgs)})
	if res.PackagePresent != domain.ClaimFalse {
		t.Fatalf("got PackagePresent=%s, want FALSE", res.PackagePresent)
	}
	// The justification must name what was probed — a bare FALSE is not
	// self-explanatory in the report.
	if len(res.CheckedPackages) != 1 || res.CheckedPackages[0] != "example.com/dep/vuln" {
		t.Fatalf("CheckedPackages=%v", res.CheckedPackages)
	}
	if len(res.CheckedModules) != 1 || res.CheckedModules[0] != "example.com/dep" {
		t.Fatalf("CheckedModules=%v", res.CheckedModules)
	}
}

// An advisory that names no affected package leaves nothing to probe —
// absence cannot be asserted from an empty check set.
func TestNoAffectedPackagesIsUnknown(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0002",
		Module: "example.com/dep",
		AffectedVersions: []domain.VersionRange{
			{Introduced: "0", Fixed: "1.2.0"},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/product"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimUnknown {
		t.Fatalf("empty probed set must not assert absence: got %s", res.PackagePresent)
	}
}

func TestModuleWithoutVersionIsUnknown(t *testing.T) {
	mods := `{"Path":"example.com/dep","Main":true}`
	res := resolve(t, fakeTool{modules: []byte(mods)})
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("main module has no version: got %s, want UNKNOWN", res.VersionAffected)
	}
}

func TestModuleListFailureIsUnknown(t *testing.T) {
	res := resolve(t, fakeTool{modErr: errors.New("build failed")})
	if res.ModulePresent != domain.ClaimUnknown || res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("tool failure must not become FALSE: %+v", res)
	}
	if len(res.Limitations) == 0 {
		t.Fatal("expected limitation describing tool failure")
	}
}

func TestPlatformConstraint(t *testing.T) {
	v := testVuln
	v.AffectedPackages = []domain.AffectedPackage{{Path: "example.com/dep/vuln", GOOS: []string{"windows"}}}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}`
	pkgs := `{"ImportPath":"example.com/dep/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.BuildRelevant != domain.ClaimFalse {
		t.Fatalf("windows-only package on linux build: got %s, want FALSE", res.BuildRelevant)
	}
}

// A multi-module advisory is resolved against the entry the product
// actually depends on — an unaffected alternative must not shield the
// affected one (GO-2022-0493: stdlib fixed by toolchain, x/sys still
// vulnerable).
func TestMultiModuleSelectsAffectedEntry(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-2022-0493",
		Module: "stdlib",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.17.10"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "syscall"}},
			},
			{
				Module:           "golang.org/x/sys",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "0.0.0-20220412"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "golang.org/x/sys/unix"}},
			},
		},
	}
	mods := `{"Path":"golang.org/x/sys","Version":"v0.0.0-20220209"}`
	pkgs := `{"ImportPath":"golang.org/x/sys/unix"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.SelectedModule != "golang.org/x/sys" {
		t.Fatalf("selected=%q", res.SelectedModule)
	}
	if res.VersionAffected != domain.ClaimTrue || res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("res=%+v", res)
	}
}

// When only the stdlib alternative applies (product toolchain fixed and
// the vendored module absent), the verdict stays deterministic-negative.
func TestMultiModuleNoEntryAffected(t *testing.T) {
	v := domain.Vulnerability{
		ID:               "GO-2022-0493",
		Module:           "stdlib",
		AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.17.10"}},
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "stdlib",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.17.10"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "syscall"}},
			},
			{
				Module:           "golang.org/x/sys",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "0.0.0-20220412"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "golang.org/x/sys/unix"}},
			},
		},
	}
	mods := `{"Path":"example.com/product","Main":true}`
	pkgs := `{"ImportPath":"example.com/product"}`
	prod := product()
	prod.GoVersion = "go version go1.26.1 linux/amd64"
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, prod)
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimFalse {
		t.Fatalf("res=%+v", res)
	}
}
