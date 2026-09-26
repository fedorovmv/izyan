package evaluator

import (
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// ConditionEvaluator assigns a TRUE/FALSE/UNKNOWN claim to a condition using
// only deterministic evidence already present in the graph.
type ConditionEvaluator interface {
	CanEvaluate(cond domain.Condition) bool
	Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim
}

// SymbolReachable evaluates SYMBOL_REACHABLE conditions from govulncheck
// call paths stored in the EvidenceGraph.
//
// Semantics per spec: a found call path to the root-cause symbol is a TRUE.
// A completed govulncheck run without such a path yields a FALSE *candidate*
// that still requires negative verification. A failed/absent run yields
// UNKNOWN — tool failure is never negative evidence.
type SymbolReachable struct{}

func (SymbolReachable) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionSymbolReachable
}

func (SymbolReachable) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer:    "evaluator.SymbolReachable",
	}
	symbols := reachabilitySubjects(cond, c)
	if len(symbols) == 0 {
		claim.Limitations = append(claim.Limitations,
			"no subject symbol: set condition.subject or resolve root cause first")
		return claim
	}

	if !govulncheckRan(c) {
		claim.Limitations = append(claim.Limitations, "govulncheck did not run or failed")
		return claim
	}

	matched := map[string]bool{}
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			for _, sym := range symbols {
				if frameMatches(fr, sym) {
					matched[sym.Package+"."+sym.Symbol] = true
					if cp.EvidenceID != "" {
						claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, cp.EvidenceID)
					}
				}
			}
		}
	}
	if len(matched) > 0 {
		claim.Result = domain.ClaimTrue
		claim.Explanation = "govulncheck produced call path(s) to the affected symbol(s)"
		return claim
	}

	// govulncheck silence only means something when the advisory was in its
	// database. If the DB lacks this advisory entirely, reachability was never
	// evaluated — fall back to module-usage evidence.
	if c.GovulncheckCoverage == "not_in_db" {
		return libraryUsageVerdict(claim, c, symbols)
	}

	claim.EvidenceIDs = nil
	claim.Result = domain.ClaimFalse
	claim.Explanation = fmt.Sprintf("govulncheck found no call path to any of %d affected symbol(s)", len(symbols))
	claim.Limitations = append(claim.Limitations,
		"FALSE is a candidate: interfaces/reflection/plugins may bypass static reachability")
	return claim
}

// libraryUsageVerdict decides reachability when govulncheck could not evaluate
// the advisory. Unexported library internals cannot be referenced by product
// code — they execute inside the library's peer-driven path, so real evidence
// is whether the product calls the module's API at all.
func libraryUsageVerdict(claim domain.Claim, c *domain.AnalysisCase, subjects []domain.SymbolRef) domain.Claim {
	usages := c.EvidenceGraph.ModuleUsages
	if len(usages) == 0 {
		claim.Result = domain.ClaimFalse
		claim.Explanation = "advisory absent from govulncheck DB and product makes no calls into the vulnerable module"
		claim.Limitations = append(claim.Limitations,
			"FALSE is a candidate: module API usage is measured from product call sites, not vendored internals")
		return claim
	}
	if allUnexported(subjects) {
		claim.Result = domain.ClaimTrue
		claim.EvidenceIDs = moduleUsageEvidence(c)
		claim.Explanation = fmt.Sprintf(
			"product calls the vulnerable module's API at %d site(s); unexported sinks execute inside its peer-driven path (advisory absent from govulncheck DB)",
			len(usages))
		claim.Limitations = append(claim.Limitations,
			"transitive reach inferred from module API usage, not traced to the sink")
		return claim
	}
	// Exported sinks: TRUE when proven reachable — either directly invoked by
	// product code, or through a traced intra-module call chain from an API
	// the product uses.
	for _, subj := range subjects {
		want := subj.Package + "." + subj.Symbol
		if chain, ok := c.EvidenceGraph.ModuleReachable[want]; ok {
			claim.Result = domain.ClaimTrue
			claim.EvidenceIDs = moduleUsageEvidence(c)
			claim.Explanation = fmt.Sprintf(
				"advisory absent from govulncheck DB; %s reachable through module internals: %s",
				want, strings.Join(chain, " -> "))
			return claim
		}
		for _, u := range usages {
			if u.Callee == want {
				claim.Result = domain.ClaimTrue
				claim.EvidenceIDs = moduleUsageEvidence(c)
				claim.Explanation = fmt.Sprintf(
					"advisory absent from govulncheck DB; product directly calls %s at %s:%d",
					want, u.File, u.Line)
				return claim
			}
		}
	}
	// FALSE only when the intra-module call graph was actually checked —
	// without it, absence is unknown, not negative.
	if !moduleReachChecked(c) {
		claim.Limitations = append(claim.Limitations,
			"advisory absent from govulncheck DB; module is used but exported sinks were not reachability-checked")
		return claim
	}
	claim.Result = domain.ClaimFalse
	claim.Explanation = fmt.Sprintf(
		"advisory absent from govulncheck DB; none of %d exported subject(s) is invoked by product code nor reachable through the module API it uses",
		len(subjects))
	claim.Limitations = append(claim.Limitations,
		"FALSE is a candidate: implicit interface dispatch (e.g. fmt.Stringer) may hide calls",
		"module-internal reachability was checked in vendored source only")
	return claim
}

// moduleReachChecked reports whether the intra-module reachability scan ran
// (its evidence record is written even when no chain was found).
func moduleReachChecked(c *domain.AnalysisCase) bool {
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Tool == "goanalysis.Index.ModuleInternalReach" && strings.Contains(e.Source, "reachability check") {
			return true
		}
	}
	return false
}

// moduleUsageEvidence returns the IDs of the module-usage evidence collected
// during evidence collection, so derived claims satisfy provenance.
func moduleUsageEvidence(c *domain.AnalysisCase) []domain.EvidenceID {
	var ids []domain.EvidenceID
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Tool == "goanalysis.Index.ModuleUsage" {
			ids = append(ids, e.ID)
		}
	}
	return ids
}

// allUnexported reports whether every subject symbol is package-internal —
// product code (and reflect/plugin lookups) cannot name them directly.
func allUnexported(subjects []domain.SymbolRef) bool {
	if len(subjects) == 0 {
		return false
	}
	for _, s := range subjects {
		name := s.Symbol
		if i := strings.LastIndexByte(name, '.'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" || name[0] < 'a' || name[0] > 'z' {
			return false
		}
	}
	return true
}

func reachabilitySubjects(cond domain.Condition, c *domain.AnalysisCase) []domain.SymbolRef {
	var out []domain.SymbolRef
	switch {
	case len(cond.Subjects) > 0:
		out = append(out, cond.Subjects...)
	case cond.Subject != nil:
		out = append(out, *cond.Subject)
	default:
		if c.Exploit != nil {
			out = append(out, c.Exploit.RootCauses...)
		}
		if len(out) == 0 && c.RootCause != nil {
			for _, rc := range c.RootCause.RootCauses {
				out = append(out, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
			}
		}
	}
	// govulncheck traces to advisory-declared vulnerable symbols, which need
	// not coincide with the fix-commit-derived root causes (e.g. a network-
	// driven library sink). The advisory symbol set defines the vulnerable
	// code, so a trace reaching any of them proves reachability.
	for _, s := range c.Vulnerability.AffectedSymbols {
		if !containsSymbol(out, s) {
			out = append(out, s)
		}
	}
	return out
}

func containsSymbol(list []domain.SymbolRef, s domain.SymbolRef) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func govulncheckRan(c *domain.AnalysisCase) bool {
	for _, e := range c.EvidenceGraph.Evidence {
		if e.Kind == domain.EvidenceGovulncheck {
			return true
		}
	}
	return false
}

func appendUniqueID(ids []domain.EvidenceID, id domain.EvidenceID) []domain.EvidenceID {
	for _, x := range ids {
		if x == id {
			return ids
		}
	}
	return append(ids, id)
}

func frameMatches(cs domain.CallSite, sym domain.SymbolRef) bool {
	if cs.Package != sym.Package {
		return false
	}
	// Symbols may be receiver-qualified ("Type.Method"); call sites carry the
	// receiver separately ("*Type" + "Method").
	if i := strings.LastIndexByte(sym.Symbol, '.'); i >= 0 {
		recv, fn := sym.Symbol[:i], sym.Symbol[i+1:]
		return cs.Function == fn && normalizeReceiver(cs.Receiver) == recv
	}
	return cs.Function == sym.Symbol
}

func normalizeReceiver(r string) string {
	r = strings.TrimPrefix(r, "(")
	r = strings.TrimSuffix(r, ")")
	return strings.TrimPrefix(r, "*")
}
