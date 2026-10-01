package evaluator

import (
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
)

// evalLocus evaluates a C-LOCUS condition — reachability of the defect
// locus set L (spec §8). TRUE follows the usual call-path evidence. FALSE
// is a candidate grounded on one falsifier only: every locus package absent
// from the snapshot's `go list -deps` build graph — code not linked cannot
// execute through any path, wrapper, callback or dispatch. A locus package
// present in the graph with no observed call path is UNKNOWN: absence of a
// package proves code is missing; a present-but-unreached function is a
// different, unproven claim.
func evalLocus(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.SymbolReachable(locus)",
	}
	// Exact locus set — unlike reachabilitySubjects, the advisory's other
	// declared symbols (enablers, path functions) do not join the subject
	// set: their reachability says nothing about the defect executing.
	symbols := append([]domain.SymbolRef(nil), cond.Subjects...)
	if len(symbols) == 0 && cond.Subject != nil {
		symbols = append(symbols, *cond.Subject)
	}
	if len(symbols) == 0 {
		claim.Limitations = append(claim.Limitations,
			"пустое множество локусов дефекта; необходимость не установлена")
		return claim
	}

	// Proposed falsifier: if the expert approves every machine non-locus
	// proposal, would the reduced locus set be fully absent from the build
	// graph? The note is advisory — it never changes this claim's result.
	proposed := proposedLocusNote(c, symbols)

	if govulncheckRan(c) {
		for _, cp := range c.EvidenceGraph.CallPaths {
			for _, fr := range cp.Frames {
				for _, sym := range symbols {
					if frameMatches(fr, sym) {
						if cp.EvidenceID != "" {
							claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, cp.EvidenceID)
						}
						claim.Result = domain.ClaimTrue
						claim.Explanation = fmt.Sprintf(
							"govulncheck call path достигает локуса дефекта %s.%s",
							sym.Package, sym.Symbol)
						if proposed != "" {
							claim.Limitations = append(claim.Limitations, proposed)
						}
						return claim
					}
				}
			}
		}
	}
	for _, subj := range symbols {
		want := subj.Package + "." + subj.Symbol
		if chain, ok := c.EvidenceGraph.ModuleReachable[want]; ok {
			claim.Result = domain.ClaimTrue
			claim.EvidenceIDs = append(moduleReachEvidence(c), moduleUsageEvidence(c)...)
			claim.Explanation = fmt.Sprintf(
				"локус дефекта %s достижим через внутренности модуля: %s",
				want, strings.Join(chain, " -> "))
			if proposed != "" {
				claim.Limitations = append(claim.Limitations, proposed)
			}
			return claim
		}
	}

	// Negative basis: complete build-graph absence of every locus package.
	set, ids, err := packageImportSet(c)
	if err != nil {
		claim.Limitations = append(claim.Limitations, err.Error())
		return claim
	}
	var present []string
	for _, s := range symbols {
		if set[s.Package] {
			present = append(present, s.Package)
		}
	}
	if len(present) > 0 {
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"пакет(ы) локуса слинкованы в граф сборки (%s); сайт дефекта присутствует в бинаре, недостижимость на уровне функции не доказана",
			strings.Join(present, ", ")))
		if proposed != "" {
			claim.Limitations = append(claim.Limitations, proposed)
		}
		return claim
	}
	claim.Result = domain.ClaimFalse
	claim.Falsifier = domain.FalsifierLocusPackageAbsent
	claim.EvidenceIDs = ids
	claim.Explanation = fmt.Sprintf(
		"все %d пакет(ов) локуса отсутствуют в графе сборки снапшота (go list -deps); уязвимый код не слинкован и не может исполниться",
		len(symbols))
	claim.Limitations = append(claim.Limitations,
		"FALSE — кандидат: отсутствие пакета ограничено build-контекстом, под которым собран package-list (GOOS/GOARCH/теги)")
	return claim
}

// packageImportSet decodes the persisted `go list -deps -json` package-list
// evidence into the set of linked import paths. Missing or undecodable
// evidence is UNKNOWN-grade — a package-loading failure never counts as
// absence.
func packageImportSet(c *domain.AnalysisCase) (map[string]bool, []domain.EvidenceID, error) {
	var ids []domain.EvidenceID
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind != domain.EvidencePackageList {
			continue
		}
		set, err := affected.PackageImportPaths([]byte(e.Content))
		if err != nil {
			return nil, nil, fmt.Errorf(
				"package-list evidence %s undecodable: %w; build-graph absence unverified", e.ID, err)
		}
		return set, append(ids, e.ID), nil
	}
	return nil, nil, fmt.Errorf(
		"нет package-list evidence (go list -deps); отсутствие в build-графе не проверено")
}

// proposedLocusNote answers the expert's review question without code
// reading: if every machine non-locus proposal were approved and recorded
// as expert basis, would the reduced locus set be fully absent from the
// persisted build graph? Returns a human-readable note or "" when no
// proposal set exists or the reduced set still has linked packages.
// The machine verifies the package-absence half; the necessity half stays
// the expert's recorded decision.
func proposedLocusNote(c *domain.AnalysisCase, symbols []domain.SymbolRef) string {
	if c.Exploit == nil || len(c.Exploit.ProposedNonLocus) == 0 {
		return ""
	}
	proposed := map[domain.SymbolRef]bool{}
	for _, d := range c.Exploit.ProposedNonLocus {
		proposed[d.Symbol] = true
	}
	var remaining []domain.SymbolRef
	var pkgs []string
	for _, s := range symbols {
		if !proposed[s] {
			remaining = append(remaining, s)
			pkgs = append(pkgs, s.Package)
		}
	}
	if len(remaining) == 0 || len(remaining) == len(symbols) {
		return ""
	}
	set, _, err := packageImportSet(c)
	if err != nil {
		return ""
	}
	for _, s := range remaining {
		if set[s.Package] {
			return ""
		}
	}
	return fmt.Sprintf(
		"предложенный falsifier ждёт утверждения эксперта: если записать %d предложенных решений non-locus, оставшиеся пакеты локуса (%s) все отсутствуют в графе `go list -deps` — следует NO_EXPLOIT_PATH_FOUND",
		len(symbols)-len(remaining), strings.Join(pkgs, ", "))
}
