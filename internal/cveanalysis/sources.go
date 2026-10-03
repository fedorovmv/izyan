// internal/cveanalysis/sources.go
package cveanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/mod/module"
)

type SourceResolver interface {
	Resolve(ctx context.Context, caseData *domain.AnalysisCase) (domain.CVESourceBundle, error)
}

type DefaultSourceResolver struct {
	cacheBaseDir string
}

func NewDefaultSourceResolver(cacheBaseDir string) *DefaultSourceResolver {
	if cacheBaseDir == "" {
		cacheBaseDir = filepath.Join(os.TempDir(), "vuln-analyzer-sources")
	}
	return &DefaultSourceResolver{cacheBaseDir: cacheBaseDir}
}

func (r *DefaultSourceResolver) Resolve(ctx context.Context, caseData *domain.AnalysisCase) (domain.CVESourceBundle, error) {
	if caseData == nil {
		return domain.CVESourceBundle{
			ManifestStatus: domain.ManifestUnavailable,
			Limitations:    []string{"nil analysis case"},
		}, fmt.Errorf("caseData cannot be nil")
	}

	vuln := caseData.Vulnerability
	bundle := domain.CVESourceBundle{
		Binding: domain.AnalysisBinding{
			AdvisoryID: vuln.ID,
		},
		ManifestStatus: domain.ManifestPartial,
		FetchedAt:      time.Now().UTC(),
	}

	// 1. Resolve patch diff from root cause or evidence graph
	if caseData.RootCause != nil && len(caseData.RootCause.FixDiff) > 0 {
		bundle.PatchDiff = caseData.RootCause.FixDiff
		h := sha256.Sum256([]byte(bundle.PatchDiff))
		bundle.Artifacts = append(bundle.Artifacts, domain.SourceArtifact{
			ID:     "patch-rootcause",
			Side:   "patch",
			Hash:   hex.EncodeToString(h[:]),
			Status: "FETCHED",
		})
	} else {
		for _, e := range caseData.EvidenceGraph.Evidence {
			if e.Kind == domain.EvidenceFixDiff && len(e.Content) > 0 {
				bundle.PatchDiff = e.Content
				h := sha256.Sum256([]byte(bundle.PatchDiff))
				bundle.Artifacts = append(bundle.Artifacts, domain.SourceArtifact{
					ID:         "patch-evidence",
					Side:       "patch",
					URI:        e.Source,
					Hash:       hex.EncodeToString(h[:]),
					Status:     "FETCHED",
					EvidenceID: e.ID,
				})
				break
			}
		}
	}

	// 2. Resolve dependency source version
	modPath := ""
	if caseData.Affected != nil && caseData.Affected.SelectedModule != "" {
		modPath = caseData.Affected.SelectedModule
	} else if vuln.Module != "" {
		modPath = vuln.Module
	} else if len(vuln.AffectedModules) > 0 && vuln.AffectedModules[0].Module != "" {
		modPath = vuln.AffectedModules[0].Module
	} else if vuln.Package != "" {
		modPath = vuln.Package
	}

	version := ""
	if caseData.Affected != nil && caseData.Affected.ResolvedVersion != "" {
		version = caseData.Affected.ResolvedVersion
	}

	bundle.Binding.Module = modPath
	bundle.Binding.ResolvedVersion = version

	if modPath != "" && version != "" {
		srcDir, err := r.locateModule(modPath, version)
		if err == nil && srcDir != "" {
			bundle.SourceDir = srcDir
			bundle.ManifestStatus = domain.ManifestComplete
		} else {
			bundle.Limitations = append(bundle.Limitations, fmt.Sprintf("source cache lookup failed: %v", err))
		}
	} else {
		bundle.Limitations = append(bundle.Limitations, "no resolved dependency module or version available")
	}

	return bundle, nil
}

func (r *DefaultSourceResolver) locateModule(modPath, version string) (string, error) {
	encPath, err := module.EscapePath(modPath)
	if err != nil {
		return "", err
	}
	encVer, err := module.EscapeVersion(version)
	if err != nil {
		return "", err
	}

	candidates := make([]string, 0, 3)
	if r.cacheBaseDir != "" {
		candidates = append(candidates, r.cacheBaseDir)
	}

	// Look in GOMODCACHE
	gomodcache := os.Getenv("GOMODCACHE")
	if gomodcache == "" {
		gopath := os.Getenv("GOPATH")
		if gopath != "" {
			gomodcache = filepath.Join(gopath, "pkg", "mod")
		}
	}
	if gomodcache != "" {
		candidates = append(candidates, gomodcache)
	}

	for _, base := range candidates {
		candidate := filepath.Join(base, encPath+"@"+encVer)
		if st, err := os.Stat(candidate); err == nil && st.IsDir() {
			return candidate, nil
		}
	}

	return "", fmt.Errorf("module %s@%s not in module cache", modPath, version)
}
