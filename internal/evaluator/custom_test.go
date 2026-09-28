package evaluator

import (
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestCustomUnroutable(t *testing.T) {
	cond := domain.Condition{ID: "C-X", Kind: domain.ConditionCustom,
		Description: "some bespoke condition"}
	cl := Custom{}.Evaluate(cond, &domain.AnalysisCase{})
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s, want UNKNOWN", cl.Result)
	}
	if !strings.Contains(cl.Limitations[0], "check=reachable") {
		t.Fatalf("limitation must name supported routes: %v", cl.Limitations)
	}
}

func TestCustomCheckShapesStayWithTheirEvaluators(t *testing.T) {
	// A CUSTOM condition carrying check=symbol_present is claimed by
	// Presence in the evaluator chain — Custom must not preempt it.
	cond := domain.Condition{ID: "C-X", Kind: domain.ConditionCustom,
		Params: map[string]string{domain.ParamCheck: domain.CheckSymbolPresent}}
	if !(Presence{}).CanEvaluate(cond) {
		t.Fatal("Presence must claim check=symbol_present regardless of kind")
	}
}

func TestCustomReadDirectionDelegates(t *testing.T) {
	cond := domain.Condition{
		ID:   "C-X",
		Kind: domain.ConditionCustom,
		Params: map[string]string{
			domain.ParamDirection: domain.DirectionRead,
		},
		Subjects: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Conn.Secret"},
		},
	}
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceSourceSnippet,
		Quality: domain.QualityDeterministic,
		Source:  "read-scope check for subjects",
		Tool:    "goanalysis.Index.SearchSymbol",
		Content: "scan",
	})
	c.EvidenceGraph.AddSymbolRefs("example.com/dep/vuln.Conn.Secret",
		domain.CallSite{File: "main.go", Line: 9})
	cl := Custom{}.Evaluate(cond, c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("result=%s want TRUE via read-direction (%s)", cl.Result, cl.Explanation)
	}
	if cl.Producer != "evaluator.Custom" {
		t.Fatalf("producer=%s", cl.Producer)
	}
}

func TestCustomReachableNoSubjects(t *testing.T) {
	// check=reachable without subjects falls through to the reachability
	// evaluator, which reports the missing subject honestly.
	cond := domain.Condition{ID: "C-X", Kind: domain.ConditionCustom,
		Params: map[string]string{domain.ParamCheck: domain.CheckReachable}}
	cl := Custom{}.Evaluate(cond, &domain.AnalysisCase{})
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s", cl.Result)
	}
	if !strings.Contains(cl.Limitations[0], "no subject") {
		t.Fatalf("lims=%v", cl.Limitations)
	}
}
