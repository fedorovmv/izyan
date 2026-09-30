package goanalysis

import (
	"fmt"
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
	return setNeg(claim, nv)
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
