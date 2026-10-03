package evaluator

import (
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Presence evaluates check=symbol_present conditions (INFO_LEAK class):
// the structure carrying sensitive fields must actually exist in the
// resolved dependency source. The presence scan (FindSymbol per subject)
// runs during evidence collection into EvidenceGraph.SymbolDecls.
//
//	TRUE  — every subject is declared in the dependency source.
//	FALSE candidate — the scan ran and at least one subject is absent;
//	  the modeled data path may not exist in this version.
//	UNKNOWN — the scan never ran or a lookup failed.
type Presence struct{}

func (Presence) CanEvaluate(cond domain.Condition) bool {
	return cond.Params[domain.ParamCheck] == domain.CheckSymbolPresent
}

func (Presence) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.Presence",
	}
	subjects := condSubjects(cond)
	if len(subjects) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no subject symbol: presence conditions bind the data structure, not root causes")
		return claim
	}
	var evIDs []domain.EvidenceID
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Tool == "goanalysis.Index.FindSymbol" && strings.HasPrefix(e.Source, "presence check ") {
			evIDs = appendUniqueID(evIDs, e.ID)
		}
	}
	if len(evIDs) == 0 {
		claim.Limitations = append(claim.Limitations,
			"presence check did not run for this condition's subjects")
		return claim
	}
	var missing, unchecked []string
	for _, s := range subjects {
		key := s.Package + "." + s.Symbol
		site, checked := c.EvidenceGraph.SymbolDeclFor(key)
		switch {
		case !checked:
			unchecked = append(unchecked, key)
		case site == nil:
			missing = append(missing, key)
		}
	}
	claim.EvidenceIDs = evIDs
	switch {
	case len(unchecked) > 0:
		claim.Limitations = append(claim.Limitations,
			"presence lookup failed or never ran for: "+strings.Join(unchecked, ", "))
	case len(missing) > 0:
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierMissingSourceSymbol
		claim.Explanation = fmt.Sprintf(
			"subject(s) absent from the resolved dependency source: %s", strings.Join(missing, ", "))
		claim.Limitations = append(claim.Limitations,
			"FALSE is a candidate: the package may exist under build tags or a different resolved version")
	default:
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf(
			"all %d subject(s) confirmed declared in the dependency source", len(subjects))
	}
	return claim
}
