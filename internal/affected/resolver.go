package affected

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Resolver performs the cheap deterministic checks from the governing spec
// (dependency exists? -> affected version? -> package present? -> build
// relevant?) and produces evidence for each step.
type Resolver interface {
	Resolve(ctx context.Context, vuln domain.Vulnerability, product domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error)
}

type GoResolver struct {
	Tool GoTool
}

func (r GoResolver) Resolve(ctx context.Context, vuln domain.Vulnerability, product domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error) {
	tool := r.Tool
	if tool == nil {
		tool = ExecGoTool{}
	}
	res := domain.AffectedResult{
		ModulePresent:   domain.ClaimUnknown,
		VersionAffected: domain.ClaimUnknown,
		PackagePresent:  domain.ClaimUnknown,
		BuildRelevant:   domain.ClaimUnknown,
	}
	var ev []domain.Evidence
	add := func(e domain.Evidence) {
		e.Repository = product.Repository
		e.Commit = product.Commit
		if e.ArtifactHash == "" && e.Content != "" {
			sum := sha256.Sum256([]byte(e.Content))
			e.ArtifactHash = hex.EncodeToString(sum[:])
		}
		res.EvidenceIDs = append(res.EvidenceIDs, e.ID)
		ev = append(ev, e)
	}

	modRaw, modSource, err := tool.ListModules(ctx, product.Repository, product)
	if err != nil {
		res.ModulePresent = domain.ClaimUnknown
		res.Limitations = append(res.Limitations, fmt.Sprintf("go list -m failed: %v", err))
		if len(modRaw) == 0 {
			return res, ev, nil
		}
	}
	add(domain.Evidence{
		ID:      "EV-AFFECTED-MODULES",
		Kind:    domain.EvidenceModuleGraph,
		Quality: domain.QualityDeterministic,
		Source:  modSource,
		Tool:    "go",
		Command: modSource,
		Content: string(modRaw),
	})
	mods, err := decodeModules(modRaw)
	if err != nil {
		res.Limitations = append(res.Limitations, fmt.Sprintf("decode module list: %v", err))
		return res, ev, nil
	}

	if isStdlibModule(vuln.Module) {
		// Standard library: "present" is decided by package import below; the
		// vulnerable version is the toolchain that compiled the release —
		// release/toolchain wins over the local go, go.mod is only a minimum.
		res.ModulePresent = domain.ClaimTrue
		res.ResolvedVersion, res.Limitations = toolchainVersion(product, res.Limitations)
		if normalizeVersion(res.ResolvedVersion) == "" {
			res.VersionAffected = domain.ClaimUnknown
			res.Limitations = append(res.Limitations,
				fmt.Sprintf("cannot apply version ranges to toolchain version %q", res.ResolvedVersion))
			return res, ev, nil
		}
		if affectedByRanges(res.ResolvedVersion, vuln.AffectedVersions) {
			res.VersionAffected = domain.ClaimTrue
		} else {
			res.VersionAffected = domain.ClaimFalse
			res.PackagePresent = domain.ClaimFalse
			res.BuildRelevant = domain.ClaimFalse
			return res, ev, nil
		}
		return resolvePackages(ctx, tool, vuln, product, res, ev, add)
	}

	mod, found := findModule(mods, vuln.Module)
	if !found {
		res.ModulePresent = domain.ClaimFalse
		res.VersionAffected = domain.ClaimFalse
		res.PackagePresent = domain.ClaimFalse
		res.BuildRelevant = domain.ClaimFalse
		return res, ev, nil
	}
	res.ModulePresent = domain.ClaimTrue
	res.ResolvedVersion = mod.EffectiveVersion()
	if mod.Replace != nil {
		res.Limitations = append(res.Limitations,
			fmt.Sprintf("module %s replaced by %s@%s", mod.Path, mod.Replace.Path, mod.Replace.Version))
	}

	if normalizeVersion(res.ResolvedVersion) == "" {
		res.VersionAffected = domain.ClaimUnknown
		res.Limitations = append(res.Limitations,
			fmt.Sprintf("cannot apply version ranges to unresolved version %q", res.ResolvedVersion))
	} else if affectedByRanges(res.ResolvedVersion, vuln.AffectedVersions) {
		res.VersionAffected = domain.ClaimTrue
	} else {
		res.VersionAffected = domain.ClaimFalse
		res.PackagePresent = domain.ClaimFalse
		res.BuildRelevant = domain.ClaimFalse
		return res, ev, nil
	}

	return resolvePackages(ctx, tool, vuln, product, res, ev, add)
}

// resolvePackages finishes the affected chain: affected package imported?
// build relevant for the snapshot's platform?
func resolvePackages(ctx context.Context, tool GoTool, vuln domain.Vulnerability,
	product domain.ProductSnapshot, res domain.AffectedResult,
	ev []domain.Evidence, add func(domain.Evidence)) (domain.AffectedResult, []domain.Evidence, error) {
	pkgRaw, err := tool.ListPackages(ctx, product.Repository, product)
	if err != nil {
		res.PackagePresent = domain.ClaimUnknown
		res.BuildRelevant = domain.ClaimUnknown
		res.Limitations = append(res.Limitations, fmt.Sprintf("go list -deps failed: %v", err))
		if len(pkgRaw) == 0 {
			return res, ev, nil
		}
	}
	add(domain.Evidence{
		ID:      "EV-AFFECTED-PACKAGES",
		Kind:    domain.EvidencePackageList,
		Quality: domain.QualityDeterministic,
		Source:  "go list -deps -test -json ./...",
		Tool:    "go",
		Command: "go list -deps -test -json ./...",
		Content: string(pkgRaw),
	})
	pkgs, err := decodePackages(pkgRaw)
	if err != nil {
		res.Limitations = append(res.Limitations, fmt.Sprintf("decode package list: %v", err))
		return res, ev, nil
	}

	affectedPkgs := affectedPackagePaths(vuln)
	present := false
	for _, want := range affectedPkgs {
		if packageImported(pkgs, want) {
			present = true
			break
		}
	}
	if present {
		res.PackagePresent = domain.ClaimTrue
	} else {
		res.PackagePresent = domain.ClaimFalse
		res.BuildRelevant = domain.ClaimFalse
		res.Limitations = append(res.Limitations,
			"package set derived from go list -deps; dynamically loaded plugins are not covered")
		return res, ev, nil
	}

	res.BuildRelevant = buildRelevant(vuln, product)
	return res, ev, nil
}

// isStdlibModule reports whether the advisory's module is the Go standard
// library or toolchain pseudo-module — such advisories apply to the release
// toolchain version, not to a module dependency.
func isStdlibModule(module string) bool {
	switch module {
	case "std", "stdlib", "toolchain", "cmd":
		return true
	}
	first := module
	if i := strings.IndexByte(module, '/'); i >= 0 {
		first = module[:i]
	}
	return !strings.Contains(first, ".")
}

// toolchainVersion picks the version the stdlib advisory applies to: the
// release toolchain (flag/binary build info) first, then the local toolchain
// used for analysis, then the go.mod minimum. Returns a semver-ish string.
func toolchainVersion(product domain.ProductSnapshot, lims []string) (string, []string) {
	if v := product.ReleaseGoVersion; v != "" {
		return v, lims
	}
	// product.GoVersion is "go version go1.26.1 darwin/arm64".
	f := strings.Fields(product.GoVersion)
	for _, tok := range f {
		if strings.HasPrefix(tok, "go1.") || strings.HasPrefix(tok, "go2.") {
			lims = append(lims,
				"stdlib version check used the analysis toolchain; pass --release-go-version or --binary for the release toolchain")
			return tok, lims
		}
	}
	if product.GoModDirective != "" {
		lims = append(lims,
			"stdlib version check fell back to the go.mod minimum — actual release toolchain unknown")
		return "go" + product.GoModDirective, lims
	}
	return "", append(lims, "no toolchain version available for stdlib advisory")
}

func findModule(mods []Module, path string) (Module, bool) {
	for _, m := range mods {
		if m.Path == path || m.EffectivePath() == path {
			return m, true
		}
	}
	return Module{}, false
}

func affectedPackagePaths(v domain.Vulnerability) []string {
	if len(v.AffectedPackages) == 0 {
		if v.Package != "" {
			return []string{v.Package}
		}
		return nil
	}
	out := make([]string, 0, len(v.AffectedPackages))
	for _, p := range v.AffectedPackages {
		out = append(out, p.Path)
	}
	return out
}

func packageImported(pkgs []Package, path string) bool {
	for _, p := range pkgs {
		if p.ImportPath == path {
			return true
		}
	}
	return false
}

// buildRelevant checks GOOS/GOARCH restrictions declared per affected import.
// A package constrained to other platforms cannot ship vulnerable code in
// this snapshot's binaries.
func buildRelevant(v domain.Vulnerability, product domain.ProductSnapshot) domain.ClaimResult {
	relevant := false
	constrained := false
	for _, p := range v.AffectedPackages {
		if len(p.GOOS) == 0 && len(p.GOARCH) == 0 {
			relevant = true
			continue
		}
		constrained = true
		if matchPlatform(product.GOOS, p.GOOS) && matchPlatform(product.GOARCH, p.GOARCH) {
			relevant = true
		}
	}
	if !constrained {
		return domain.ClaimTrue
	}
	if relevant {
		return domain.ClaimTrue
	}
	return domain.ClaimFalse
}

func matchPlatform(have string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if a == have {
			return true
		}
	}
	return false
}
