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

func (f fakeTool) ListModules(context.Context, string, domain.ProductSnapshot) ([]byte, error) {
	return f.modules, f.modErr
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
