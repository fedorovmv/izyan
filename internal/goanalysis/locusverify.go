package goanalysis

import (
	"fmt"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
)

// verifyLocusAbsent re-checks the locus-package-absent falsifier against
// the persisted build-graph evidence: every locus subject's package must be
// absent from `go list -deps`. A locus package found linked contradicts the
// FALSE; missing or undecodable package-list evidence leaves the scope
// insufficient — a loading failure is never absence.
//
// Unlike the subject-escape checks this verification needs no source index:
// the falsifier's premise is the build graph itself, so package absence
// cannot be escaped by wrappers, callbacks or dynamic dispatch.
func (v Verifier) verifyLocusAbsent(c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition) domain.Claim {

	subjects := append([]domain.SymbolRef{}, cond.Subjects...)
	if cond.Subject != nil {
		subjects = append(subjects, *cond.Subject)
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	if len(subjects) == 0 {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "no locus subjects on condition",
		})
	}

	set, evID, err := packageImportSet(c)
	if err != nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status:      domain.NegativeInsufficientScope,
			EvidenceIDs: append([]domain.EvidenceID(nil), claim.EvidenceIDs...),
			Notes:       err.Error(),
		})
	}
	nv.EvidenceIDs = append(nv.EvidenceIDs, evID)

	var present []string
	for _, s := range subjects {
		if set[s.Package] {
			present = append(present, s.Package)
		}
	}
	if len(present) > 0 {
		nv.Status = domain.NegativeContradicted
		nv.Notes = fmt.Sprintf(
			"locus package(s) %s are linked into the snapshot build graph; "+
				"the defect code is present and package-absence does not hold",
			strings.Join(present, ", "))
		return setNeg(claim, nv)
	}
	nv.Notes = fmt.Sprintf(
		"all %d defect-locus package(s) absent from the go list -deps build graph", len(subjects))
	nv.Limitations = append(nv.Limitations,
		"absence verified under the build context the package list was produced with (GOOS/GOARCH/tags); other configurations may link the package")

	// Coverage gap check: files excluded under the recorded build context
	// (other GOOS/GOARCH, build tags, cgo) may still import a locus package
	// — the product could be built in a configuration where the code links.
	// Absence in one context is not absence in the product.
	if gap := excludedBuildImports(c, subjects); gap != "" {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes += "; " + gap
		return setNeg(claim, nv)
	}

	if c.Exploit != nil && len(c.Exploit.NonLocusBasis) > 0 {
		var names []string
		for _, d := range c.Exploit.NonLocusBasis {
			names = append(names, d.Symbol.Package+"."+d.Symbol.Symbol)
		}
		nv.Limitations = append(nv.Limitations, fmt.Sprintf(
			"locus coverage reduced by expert non-locus decisions (not machine evidence): %s",
			strings.Join(names, ", ")))
	}
	return setNeg(claim, nv)
}

// excludedBuildImports scans the product tree for Go source files that the
// recorded build context excludes (build tags, GOOS/GOARCH filename
// suffixes, cgo rules) but which import a locus package. Their presence
// means a different build configuration links code the package list never
// saw — the absence proof is then scoped to the recorded context only.
// Directories the go tool never builds (vendor, testdata, _/.-prefixed)
// are skipped: excluded files there can never join a product build.
func excludedBuildImports(c *domain.AnalysisCase, subjects []domain.SymbolRef) string {
	root := c.Product.Repository
	if root == "" {
		return ""
	}
	locusPkgs := map[string]bool{}
	for _, s := range subjects {
		locusPkgs[s.Package] = true
	}
	ctx := build.Default
	if c.Product.GOOS != "" {
		ctx.GOOS = c.Product.GOOS
	}
	if c.Product.GOARCH != "" {
		ctx.GOARCH = c.Product.GOARCH
	}
	ctx.BuildTags = append([]string(nil), c.Product.BuildTags...)
	ctx.CgoEnabled = c.Product.CGOEnabled

	var gaps []string
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := d.Name()
			if base == ".git" || base == "vendor" || base == "testdata" ||
				strings.HasPrefix(base, "_") || (strings.HasPrefix(base, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			// Test files never link into the product binary under any
			// configuration — an excluded test importing the package is
			// not a coverage gap for exploitation.
			return nil
		}
		dir := filepath.Dir(path)
		match, merr := ctx.MatchFile(dir, d.Name())
		if merr == nil && match {
			return nil // part of the recorded build — the package list covers it
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return nil // cannot compile in any configuration — links nothing
		}
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if locusPkgs[p] {
				rel, rerr := filepath.Rel(root, path)
				if rerr != nil {
					rel = path
				}
				gaps = append(gaps, rel+"→"+p)
				break
			}
		}
		return nil
	})
	if len(gaps) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"product file(s) excluded under the recorded build context import locus package(s): %s — "+
			"a build with different tags/GOOS/GOARCH/cgo would link them",
		strings.Join(gaps, ", "))
}

// packageImportSet decodes the persisted `go list -deps -json` evidence into
// the set of import paths the snapshot links.
func packageImportSet(c *domain.AnalysisCase) (map[string]bool, domain.EvidenceID, error) {
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind != domain.EvidencePackageList {
			continue
		}
		set, err := affected.PackageImportPaths([]byte(e.Content))
		if err != nil {
			return nil, "", fmt.Errorf(
				"package-list evidence %s undecodable: %w; build-graph absence unverified", e.ID, err)
		}
		return set, e.ID, nil
	}
	return nil, "", fmt.Errorf(
		"no package-list evidence (go list -deps); build-graph absence unverified")
}
