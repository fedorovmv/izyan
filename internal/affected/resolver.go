package affected

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
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
		e = withAudit(e, product)
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
	mods, err := DecodeModules(modRaw)
	if err != nil {
		res.Limitations = append(res.Limitations, fmt.Sprintf("decode module list: %v", err))
		return res, ev, nil
	}

	// Multi-module advisories carry alternative entries (e.g. stdlib plus
	// the vendored module shipping the same fix); the applicable one is
	// whichever module the product actually resolves. Evaluate every
	// entry's presence+version, then continue with the affected entry —
	// an unaffected alternative does not shield an affected one.
	entries := affectedModuleEntries(vuln)
	for _, e := range entries {
		res.CheckedModules = append(res.CheckedModules, e.Module)
	}
	var selected *domain.AffectedModule
	var selectedModules []string
	verUnknown := false
	for i := range entries {
		e := &entries[i]
		if isStdlibModule(e.Module) {
			// Standard library: the vulnerable version is the toolchain
			// that compiled the release — release/toolchain wins over the
			// local go, go.mod is only a minimum.
			res.ModulePresent = domain.ClaimTrue
			ver, lims := toolchainVersion(product, res.Limitations)
			res.Limitations = lims
			if normalizeVersion(ver) == "" {
				res.Limitations = append(res.Limitations,
					fmt.Sprintf("cannot apply version ranges to toolchain version %q", ver))
				verUnknown = true
				continue
			}
			selectedModules = append(selectedModules, e.Module+"@"+ver)
			if affectedByRanges(ver, e.AffectedVersions) && selected == nil {
				selected = e
				res.ResolvedVersion = ver
			}
			continue
		}
		mod, found := findModule(mods, e.Module)
		if !found {
			continue
		}
		res.ModulePresent = domain.ClaimTrue
		res.ResolvedVersion = mod.EffectiveVersion()
		if mod.Replace != nil {
			res.Limitations = append(res.Limitations,
				fmt.Sprintf("module %s replaced by %s@%s", mod.Path, mod.Replace.Path, mod.Replace.Version))
		}
		selectedModules = append(selectedModules, e.Module+"@"+mod.EffectiveVersion())
		if normalizeVersion(mod.EffectiveVersion()) == "" {
			res.Limitations = append(res.Limitations,
				fmt.Sprintf("cannot apply version ranges to unresolved version %q", mod.EffectiveVersion()))
			verUnknown = true
			continue
		}
		if affectedByRanges(mod.EffectiveVersion(), e.AffectedVersions) && selected == nil {
			selected = e
		}
	}

	if res.ModulePresent == domain.ClaimUnknown && len(entries) > 0 {
		// Every entry was either a module absent from the graph or a
		// stdlib check that resolved — absence of all module entries is
		// deterministic evidence of non-applicability.
		res.ModulePresent = domain.ClaimFalse
	}
	if res.ModulePresent == domain.ClaimFalse {
		res.VersionAffected = domain.ClaimFalse
		res.PackagePresent = domain.ClaimFalse
		res.BuildRelevant = domain.ClaimFalse
		return res, ev, nil
	}
	if selected == nil {
		if verUnknown {
			// A present entry's version could not be resolved — its
			// applicability is undecided, not refuted.
			res.VersionAffected = domain.ClaimUnknown
			return res, ev, nil
		}
		res.VersionAffected = domain.ClaimFalse
		res.PackagePresent = domain.ClaimFalse
		res.BuildRelevant = domain.ClaimFalse
		if len(selectedModules) > 0 {
			res.Limitations = append(res.Limitations,
				"evaluated affected-module entries: "+strings.Join(selectedModules, ", "))
		}
		return res, ev, nil
	}
	res.SelectedModule = selected.Module
	res.VersionAffected = domain.ClaimTrue
	if len(entries) > 1 {
		res.Limitations = append(res.Limitations,
			fmt.Sprintf("multi-module advisory: resolved against %s (entries evaluated: %s)",
				selected.Module, strings.Join(selectedModules, ", ")))
	}

	return resolvePackages(ctx, tool, selected.AffectedPackages, product, res, ev)
}

// withAudit stamps the evidence with the product identity and a content
// hash — shared by every evidence-producing step of the resolver.
func withAudit(e domain.Evidence, product domain.ProductSnapshot) domain.Evidence {
	e.Repository = product.Repository
	e.Commit = product.Commit
	if e.ArtifactHash == "" && e.Content != "" {
		sum := sha256.Sum256([]byte(e.Content))
		e.ArtifactHash = hex.EncodeToString(sum[:])
	}
	return e
}

// affectedModuleEntries returns the advisory's per-module affected entries,
// synthesizing a single entry from the flat fields for non-OSV intakes.
func affectedModuleEntries(vuln domain.Vulnerability) []domain.AffectedModule {
	if len(vuln.AffectedModules) > 0 {
		return vuln.AffectedModules
	}
	if vuln.Module == "" {
		return nil
	}
	return []domain.AffectedModule{{
		Module:           vuln.Module,
		AffectedVersions: vuln.AffectedVersions,
		FixedVersions:    vuln.FixedVersions,
		AffectedPackages: vuln.AffectedPackages,
		AffectedSymbols:  vuln.AffectedSymbols,
	}}
}

// resolvePackages finishes the affected chain: affected package imported?
// build relevant for the snapshot's platform? affected is the selected
// entry's package set — multi-module advisories scope it per module.
func resolvePackages(ctx context.Context, tool GoTool, affectedPkgs []domain.AffectedPackage,
	product domain.ProductSnapshot, res domain.AffectedResult,
	ev []domain.Evidence) (domain.AffectedResult, []domain.Evidence, error) {
	// Local add: res/ev here are copies — appending through the caller's
	// closure would land evidence on values that never get returned.
	add := func(e domain.Evidence) {
		e = withAudit(e, product)
		res.EvidenceIDs = append(res.EvidenceIDs, e.ID)
		ev = append(ev, e)
	}
	affectedPaths := affectedPackagePaths(affectedPkgs)
	res.CheckedPackages = affectedPaths
	if len(affectedPaths) == 0 {
		// The advisory names no affected package for the selected module —
		// nothing concrete to probe, so absence cannot be asserted.
		res.PackagePresent = domain.ClaimUnknown
		res.BuildRelevant = domain.ClaimUnknown
		res.Limitations = append(res.Limitations,
			"advisory names no affected packages for the selected module; package presence undecidable")
		return res, ev, nil
	}
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

	present := false
	for _, want := range affectedPaths {
		if packageImported(pkgs, want) {
			present = true
			break
		}
	}
	if present {
		res.PackagePresent = domain.ClaimTrue
	} else {
		// A package absent from this build can still be imported by
		// build-tag-excluded files — "not imported" then holds only for
		// the analyzed configuration, which cannot ground NOT_AFFECTED.
		// The same applies when an excluded file could not be read:
		// an unchecked file is unknown evidence, not evidence of absence.
		gated, incomplete := gatedImports(pkgs, affectedPaths)
		if len(gated) > 0 {
			res.PackagePresent = domain.ClaimUnknown
			res.BuildRelevant = domain.ClaimUnknown
			res.Limitations = append(res.Limitations, fmt.Sprintf(
				"affected package imported by build-constraint-excluded file(s) %s; package presence depends on build tags",
				strings.Join(gated, ", ")))
			return res, ev, nil
		}
		if incomplete {
			res.PackagePresent = domain.ClaimUnknown
			res.BuildRelevant = domain.ClaimUnknown
			res.Limitations = append(res.Limitations,
				"build-constraint-excluded file(s) could not be parsed; affected-package presence unverified")
			return res, ev, nil
		}
		res.PackagePresent = domain.ClaimFalse
		res.BuildRelevant = domain.ClaimFalse
		res.Limitations = append(res.Limitations,
			"package set derived from go list -deps; dynamically loaded plugins are not covered")
		return res, ev, nil
	}

	res.BuildRelevant = buildRelevant(affectedPkgs, product)
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

func affectedPackagePaths(pkgs []domain.AffectedPackage) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
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

// gatedImports returns the product files excluded by build constraints
// whose import lists name an affected package, plus whether any excluded
// file could not be inspected (unreadable/unparseable — an unknown, not
// an absence). Only non-DepOnly (product root) packages carry
// IgnoredGoFiles; dependency internals are irrelevant — a dep's own gated
// files do not change whether the product links the affected package.
func gatedImports(pkgs []Package, affected []string) ([]string, bool) {
	var found []string
	incomplete := false
	for _, p := range pkgs {
		if p.DepOnly || p.Dir == "" || len(p.IgnoredGoFiles) == 0 {
			continue
		}
		for _, f := range p.IgnoredGoFiles {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := parser.ParseFile(token.NewFileSet(),
				filepath.Join(p.Dir, f), nil, parser.ImportsOnly)
			if err != nil {
				incomplete = true
				continue
			}
			for _, imp := range src.Imports {
				path, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					incomplete = true
					continue
				}
				for _, want := range affected {
					if path == want {
						found = append(found, p.ImportPath+":"+f)
					}
				}
			}
		}
	}
	return found, incomplete
}

// buildRelevant checks GOOS/GOARCH restrictions declared per affected import.
// A package constrained to other platforms cannot ship vulnerable code in
// this snapshot's binaries.
func buildRelevant(pkgs []domain.AffectedPackage, product domain.ProductSnapshot) domain.ClaimResult {
	relevant := false
	constrained := false
	for _, p := range pkgs {
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
