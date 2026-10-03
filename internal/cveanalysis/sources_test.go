// internal/cveanalysis/sources_test.go
package cveanalysis_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/cveanalysis"
	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/mod/module"
)

func TestSourceResolver_ProductGoModImmutability(t *testing.T) {
	tmpDir := t.TempDir()
	productGoMod := filepath.Join(tmpDir, "go.mod")
	initialContent := []byte("module example.com/product\n\ngo 1.22\n")
	if err := os.WriteFile(productGoMod, initialContent, 0644); err != nil {
		t.Fatal(err)
	}

	hBefore := sha256.Sum256(initialContent)
	expectedHash := hex.EncodeToString(hBefore[:])

	caseData := &domain.AnalysisCase{
		Product: domain.ProductSnapshot{
			Repository: tmpDir,
		},
		Vulnerability: domain.Vulnerability{
			ID: "GO-TEST-0001",
		},
	}

	cacheDir := filepath.Join(tmpDir, "cache")
	resolver := cveanalysis.NewDefaultSourceResolver(cacheDir)

	_, _ = resolver.Resolve(context.Background(), caseData)

	afterContent, err := os.ReadFile(productGoMod)
	if err != nil {
		t.Fatal(err)
	}
	hAfter := sha256.Sum256(afterContent)
	actualHash := hex.EncodeToString(hAfter[:])

	if actualHash != expectedHash {
		t.Fatalf("product go.mod was mutated! before: %s, after: %s", expectedHash, actualHash)
	}
}

func TestSourceResolver_ResolveWithModuleCache(t *testing.T) {
	tmpDir := t.TempDir()
	cacheDir := filepath.Join(tmpDir, "cache")

	modPath := "github.com/Azure/azure-sdk-for-go"
	version := "v1.2.3"

	encPath, err := module.EscapePath(modPath)
	if err != nil {
		t.Fatalf("escape path failed: %v", err)
	}
	encVer, err := module.EscapeVersion(version)
	if err != nil {
		t.Fatalf("escape version failed: %v", err)
	}

	expectedDir := filepath.Join(cacheDir, encPath+"@"+encVer)
	if err := os.MkdirAll(expectedDir, 0755); err != nil {
		t.Fatal(err)
	}
	dummyFile := filepath.Join(expectedDir, "azure.go")
	if err := os.WriteFile(dummyFile, []byte("package azure\n"), 0644); err != nil {
		t.Fatal(err)
	}

	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2026-9999",
			Module: modPath,
		},
		Affected: &domain.AffectedResult{
			ResolvedVersion: version,
		},
	}

	resolver := cveanalysis.NewDefaultSourceResolver(cacheDir)
	bundle, err := resolver.Resolve(context.Background(), caseData)
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}

	if bundle.Binding.AdvisoryID != "GO-2026-9999" {
		t.Errorf("got AdvisoryID %q, want GO-2026-9999", bundle.Binding.AdvisoryID)
	}
	if bundle.Binding.Module != modPath {
		t.Errorf("got Module %q, want %q", bundle.Binding.Module, modPath)
	}
	if bundle.Binding.ResolvedVersion != version {
		t.Errorf("got ResolvedVersion %q, want %q", bundle.Binding.ResolvedVersion, version)
	}
	if bundle.ManifestStatus != domain.ManifestComplete {
		t.Errorf("got ManifestStatus %v, want COMPLETE", bundle.ManifestStatus)
	}
	if bundle.SourceDir != expectedDir {
		t.Errorf("got SourceDir %q, want %q", bundle.SourceDir, expectedDir)
	}
	if bundle.FetchedAt.IsZero() {
		t.Error("expected non-zero FetchedAt")
	}
	if len(bundle.Limitations) != 0 {
		t.Errorf("unexpected limitations: %v", bundle.Limitations)
	}
}

func TestSourceResolver_ResolvePatchDiff_RootCause(t *testing.T) {
	patchContent := "diff --git a/vuln.go b/vuln.go\n--- a/vuln.go\n+++ b/vuln.go\n@@ -1 +1 @@\n-broken\n+fixed\n"
	h := sha256.Sum256([]byte(patchContent))
	expectedHash := hex.EncodeToString(h[:])

	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID: "GO-2026-0002",
		},
		RootCause: &domain.RootCauseModel{
			FixDiff: patchContent,
		},
	}

	resolver := cveanalysis.NewDefaultSourceResolver(t.TempDir())
	bundle, err := resolver.Resolve(context.Background(), caseData)
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}

	if bundle.PatchDiff != patchContent {
		t.Errorf("got PatchDiff %q, want %q", bundle.PatchDiff, patchContent)
	}
	if len(bundle.Artifacts) != 1 {
		t.Fatalf("got %d artifacts, want 1", len(bundle.Artifacts))
	}
	art := bundle.Artifacts[0]
	if art.ID != "patch-rootcause" {
		t.Errorf("got artifact ID %q, want patch-rootcause", art.ID)
	}
	if art.Side != "patch" {
		t.Errorf("got artifact Side %q, want patch", art.Side)
	}
	if art.Status != "FETCHED" {
		t.Errorf("got artifact Status %q, want FETCHED", art.Status)
	}
	if art.Hash != expectedHash {
		t.Errorf("got artifact Hash %q, want %q", art.Hash, expectedHash)
	}
}

func TestSourceResolver_ResolvePatchDiff_EvidenceGraph(t *testing.T) {
	patchContent := "diff --git a/fix.go b/fix.go\n+safe\n"
	h := sha256.Sum256([]byte(patchContent))
	expectedHash := hex.EncodeToString(h[:])

	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID: "GO-2026-0003",
		},
		EvidenceGraph: domain.EvidenceGraph{
			Evidence: []domain.Evidence{
				{
					ID:      "EV-FIX-1",
					Kind:    domain.EvidenceFixDiff,
					Source:  "https://github.com/example/repo/commit/abc.patch",
					Content: patchContent,
				},
			},
		},
	}

	resolver := cveanalysis.NewDefaultSourceResolver(t.TempDir())
	bundle, err := resolver.Resolve(context.Background(), caseData)
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}

	if bundle.PatchDiff != patchContent {
		t.Errorf("got PatchDiff %q, want %q", bundle.PatchDiff, patchContent)
	}
	if len(bundle.Artifacts) != 1 {
		t.Fatalf("got %d artifacts, want 1", len(bundle.Artifacts))
	}
	art := bundle.Artifacts[0]
	if art.ID != "patch-evidence" {
		t.Errorf("got artifact ID %q, want patch-evidence", art.ID)
	}
	if art.URI != "https://github.com/example/repo/commit/abc.patch" {
		t.Errorf("got artifact URI %q, want https://github.com/example/repo/commit/abc.patch", art.URI)
	}
	if art.Hash != expectedHash {
		t.Errorf("got artifact Hash %q, want %q", art.Hash, expectedHash)
	}
	if art.EvidenceID != "EV-FIX-1" {
		t.Errorf("got EvidenceID %q, want EV-FIX-1", art.EvidenceID)
	}
}

func TestSourceResolver_MissingModule(t *testing.T) {
	cacheDir := t.TempDir()
	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2026-0004",
			Module: "example.com/nonexistent/module",
		},
		Affected: &domain.AffectedResult{
			ResolvedVersion: "v1.0.0",
		},
	}

	resolver := cveanalysis.NewDefaultSourceResolver(cacheDir)
	bundle, err := resolver.Resolve(context.Background(), caseData)
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}

	if bundle.ManifestStatus != domain.ManifestPartial {
		t.Errorf("got ManifestStatus %v, want PARTIAL", bundle.ManifestStatus)
	}
	if bundle.SourceDir != "" {
		t.Errorf("got SourceDir %q, want empty", bundle.SourceDir)
	}
	if len(bundle.Limitations) != 1 || !strings.Contains(bundle.Limitations[0], "source cache lookup failed") {
		t.Errorf("expected source cache lookup failure in limitations, got: %v", bundle.Limitations)
	}
}

func TestSourceResolver_NoModuleOrVersion(t *testing.T) {
	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID: "GO-2026-0005",
		},
	}

	resolver := cveanalysis.NewDefaultSourceResolver(t.TempDir())
	bundle, err := resolver.Resolve(context.Background(), caseData)
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}

	if bundle.ManifestStatus != domain.ManifestPartial {
		t.Errorf("got ManifestStatus %v, want PARTIAL", bundle.ManifestStatus)
	}
	if len(bundle.Limitations) != 1 || !strings.Contains(bundle.Limitations[0], "no resolved dependency module or version available") {
		t.Errorf("expected missing module/version limitation, got: %v", bundle.Limitations)
	}
}

func TestSourceResolver_NilCaseData(t *testing.T) {
	resolver := cveanalysis.NewDefaultSourceResolver(t.TempDir())
	bundle, err := resolver.Resolve(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error on nil caseData, got nil")
	}
	if bundle.ManifestStatus != domain.ManifestUnavailable {
		t.Errorf("got ManifestStatus %v, want UNAVAILABLE", bundle.ManifestStatus)
	}
}

func TestSourceResolver_ResolveWithGOMODCACHE(t *testing.T) {
	gomodcacheDir := t.TempDir()
	t.Setenv("GOMODCACHE", gomodcacheDir)

	modPath := "github.com/google/uuid"
	version := "v1.3.0"

	encPath, err := module.EscapePath(modPath)
	if err != nil {
		t.Fatalf("escape path failed: %v", err)
	}
	encVer, err := module.EscapeVersion(version)
	if err != nil {
		t.Fatalf("escape version failed: %v", err)
	}

	expectedDir := filepath.Join(gomodcacheDir, encPath+"@"+encVer)
	if err := os.MkdirAll(expectedDir, 0755); err != nil {
		t.Fatal(err)
	}

	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2026-1234",
			Module: modPath,
		},
		Affected: &domain.AffectedResult{
			ResolvedVersion: version,
		},
	}

	// resolver with separate empty cacheBaseDir; should fallback to GOMODCACHE
	resolver := cveanalysis.NewDefaultSourceResolver(t.TempDir())
	bundle, err := resolver.Resolve(context.Background(), caseData)
	if err != nil {
		t.Fatalf("Resolve returned unexpected error: %v", err)
	}

	if bundle.ManifestStatus != domain.ManifestComplete {
		t.Errorf("got ManifestStatus %v, want COMPLETE", bundle.ManifestStatus)
	}
	if bundle.SourceDir != expectedDir {
		t.Errorf("got SourceDir %q, want %q", bundle.SourceDir, expectedDir)
	}
}
