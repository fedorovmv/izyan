package evaluator

import (
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
)

// evalLocus evaluates a C-LOCUS condition — reachability of the defect
// locus set L (spec §8). TRUE follows the usual call-path evidence. FALSE
// is a candidate grounded on two falsifiers: every locus package absent from
// the snapshot's `go list -deps` build graph (locus-package-absent), or locus
// packages linked into the graph but symbols in L having zero call traces or
// module chains (locus-function-unreached).
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
			"пустой список уязвимых функций; необходимость не установлена")
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
							"трасса вызовов govulncheck достигает уязвимой функции %s.%s",
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
				"уязвимая функция %s достижима через вызовы внутри модуля: %s",
				want, strings.Join(chain, " -> "))
			if proposed != "" {
				claim.Limitations = append(claim.Limitations, proposed)
			}
			return claim
		}
	}

	// Negative basis: complete build-graph absence of every locus package,
	// or function unreachability when locus packages are linked.
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
		hasCallPath := false
		for _, cp := range c.EvidenceGraph.CallPaths {
			for _, fr := range cp.Frames {
				for _, sym := range symbols {
					if frameMatches(fr, sym) {
						hasCallPath = true
						break
					}
				}
			}
		}
		hasModuleReach := false
		for _, subj := range symbols {
			want := subj.Package + "." + subj.Symbol
			if _, ok := c.EvidenceGraph.ModuleReachable[want]; ok {
				hasModuleReach = true
				break
			}
		}
		if !hasCallPath && !hasModuleReach {
			claim.Result = domain.ClaimFalse
			claim.Falsifier = domain.FalsifierLocusFunctionUnreached
			claim.EvidenceIDs = ids
			claim.Explanation = fmt.Sprintf(
				"пакеты с уязвимым кодом входят в сборку, но функции дефектного локуса (%d) не имеют обнаруженных трасс вызовов; требуется верификация недостижимости",
				len(symbols))
			claim.Limitations = append(claim.Limitations,
				"FALSE (предварительно): недостижимость функции в скомпилированном пакете требует негативной верификации")
			if proposed != "" {
				claim.Limitations = append(claim.Limitations, proposed)
			}
			return claim
		}
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"пакеты с уязвимым кодом входят в граф сборки (%s); код включён в бинарник, недостижимость на уровне функции не доказана",
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
		"все пакеты с уязвимым кодом (%d) отсутствуют в графе сборки (go list -deps); уязвимый код не скомпилирован в приложение и не может выполниться",
		len(symbols))
	claim.Limitations = append(claim.Limitations,
		"FALSE (предварительно): отсутствие пакета проверено для текущего контекста сборки (GOOS/GOARCH/теги)")
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
				"не удалось прочитать список пакетов %s: %w; отсутствие в графе сборки не проверено", e.ID, err)
		}
		return set, append(ids, e.ID), nil
	}
	return nil, nil, fmt.Errorf(
		"нет данных о составе сборки (go list -deps); отсутствие в графе сборки не проверено")
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
		"предварительный вывод ждёт подтверждения эксперта: если утвердить %d предложенных решений `non_locus`, все остальные пакеты с уязвимым кодом (%s) отсутствуют в сборке (`go list -deps`) → следует NO_EXPLOIT_PATH_FOUND",
		len(symbols)-len(remaining), strings.Join(pkgs, ", "))
}
