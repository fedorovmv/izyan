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

// Two version-affected entries are alternatives, not a sequence: the
// package probe covers all of them, and a hit narrows to the owning
// module. A first entry whose package is absent must not shield the
// second one's imported package.
func TestMultiAffectedEntriesUnionProbe(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0003",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other","Version":"v1.5.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/other/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("second affected entry's package is imported: got PackagePresent=%s", res.PackagePresent)
	}
	if res.SelectedModule != "example.com/other" {
		t.Fatalf("SelectedModule=%q, want the imported entry's module", res.SelectedModule)
	}
	if len(res.CheckedPackages) != 2 {
		t.Fatalf("union probe expected, CheckedPackages=%v", res.CheckedPackages)
	}
}

// When BOTH entries' packages are imported the vulnerable path exists in
// each module — SelectedModules must carry both, so downstream narrowing
// cannot drop the second entry's symbols.
func TestMultiAffectedBothImported(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0003b",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other","Version":"v1.5.0"}`
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/dep/vuln"}
{"ImportPath":"example.com/other/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("got PackagePresent=%s", res.PackagePresent)
	}
	if len(res.SelectedModules) != 2 {
		t.Fatalf("both modules imported: SelectedModules=%v", res.SelectedModules)
	}
}

// A version-undecidable module still gets its packages probed: when the
// confirmed entry's package is absent but the pending entry's package is
// linked, PackagePresent=FALSE would be a false NOT_AFFECTED.
func TestPendingModulePackageProbe(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0003c",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other"}` // no Version — ranges unresolvable
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/other/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.PackagePresent != domain.ClaimTrue {
		t.Fatalf("pending entry's imported package must keep the case open, got PackagePresent=%s", res.PackagePresent)
	}
	found := false
	for _, m := range res.SelectedModules {
		if m == "example.com/other" {
			found = true
		}
	}
	if !found {
		t.Fatalf("pending module must land in SelectedModules: %v", res.SelectedModules)
	}
	// Only the pending module's code is linked — the confirmed version
	// verdict belongs to the unlinked entry and must not carry over.
	if res.VersionAffected != domain.ClaimUnknown {
		t.Fatalf("VersionAffected=%s — undecidable, the linked module's version is unresolved", res.VersionAffected)
	}
	if res.ResolvedVersion != "" {
		t.Fatalf("ResolvedVersion=%q still names the unlinked module's version", res.ResolvedVersion)
	}
}

// Flat intake that names only Vulnerability.Package still probes that
// package — the fallback must survive multi-module normalization.
func TestFlatPackageFallback(t *testing.T) {
	v := domain.Vulnerability{
		ID:      "GO-0000-0004",
		Module:  "example.com/dep",
		Package: "example.com/dep/vuln",
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
	if len(res.CheckedPackages) != 1 || res.CheckedPackages[0] != "example.com/dep/vuln" {
		t.Fatalf("Package fallback lost: CheckedPackages=%v", res.CheckedPackages)
	}
	if res.PackagePresent != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE over the fallback probe", res.PackagePresent)
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

// Both modules linked — confirmed AND pending: the version stays TRUE
// (attributed to the confirmed module) and PendingModules names the
// undecidable one so version facts cannot be consumed as its fact.
func TestPendingModuleMixedLink(t *testing.T) {
	v := domain.Vulnerability{
		ID:     "GO-0000-0003d",
		Module: "example.com/dep",
		AffectedModules: []domain.AffectedModule{
			{
				Module:           "example.com/dep",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "1.2.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/dep/vuln"}},
			},
			{
				Module:           "example.com/other",
				AffectedVersions: []domain.VersionRange{{Introduced: "0", Fixed: "2.0.0"}},
				AffectedPackages: []domain.AffectedPackage{{Path: "example.com/other/vuln"}},
			},
		},
	}
	mods := `{"Path":"example.com/dep","Version":"v1.0.0"}
{"Path":"example.com/other"}` // no Version — pending
	pkgs := `{"ImportPath":"example.com/product"}
{"ImportPath":"example.com/dep/vuln"}
{"ImportPath":"example.com/other/vuln"}`
	res, _, err := GoResolver{Tool: fakeTool{modules: []byte(mods), packages: []byte(pkgs)}}.
		Resolve(context.Background(), v, product())
	if err != nil {
		t.Fatal(err)
	}
	if res.VersionAffected != domain.ClaimTrue {
		t.Fatalf("confirmed module linked — VersionAffected=%s", res.VersionAffected)
	}
	if res.SelectedModule != "example.com/dep" || res.ResolvedVersion != "v1.0.0" {
		t.Fatalf("version pair must pin to the confirmed module: %s@%s", res.SelectedModule, res.ResolvedVersion)
	}
	if len(res.PendingModules) != 1 || res.PendingModules[0] != "example.com/other" {
		t.Fatalf("PendingModules=%v — linked pending module must be named", res.PendingModules)
	}
}
