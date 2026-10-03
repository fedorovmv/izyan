package evaluator

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func seqCond() domain.Condition {
	return domain.Condition{
		ID:   "C-ROUNDTRIP",
		Kind: domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{
			{Package: "mod/amqp", Symbol: "URI.String"},
			{Package: "mod/amqp", Symbol: "ParseURI"},
		},
		Params: map[string]string{
			domain.ParamSequence: "mod/amqp.URI.String->mod/amqp.ParseURI",
		},
	}
}

func readCond() domain.Condition {
	return domain.Condition{
		ID:   "C-EXPOSED",
		Kind: domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{
			{Package: "mod/amqp", Symbol: "PlainAuth.Password"},
		},
		Params: map[string]string{domain.ParamDirection: domain.DirectionRead},
	}
}

func presentCond() domain.Condition {
	return domain.Condition{
		ID:   "C-DATA-PRESENT",
		Kind: domain.ConditionConfiguration,
		Subjects: []domain.SymbolRef{
			{Package: "mod/amqp", Symbol: "PlainAuth"},
		},
		Params: map[string]string{domain.ParamCheck: domain.CheckSymbolPresent},
	}
}

func usageCheck(c *domain.AnalysisCase) {
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID:   "EV-USE",
		Kind: domain.EvidenceSourceSnippet,
		Tool: "goanalysis.Index.ModuleUsage",
	})
}

func readCheck(c *domain.AnalysisCase) {
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID:     "EV-READ",
		Kind:   domain.EvidenceSearchResult,
		Tool:   "goanalysis.Index.SearchSymbol",
		Source: "read-scope check mod/amqp.PlainAuth.Password",
	})
}

func presenceCheck(c *domain.AnalysisCase) {
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID:     "EV-PRES",
		Kind:   domain.EvidenceSearchResult,
		Tool:   "goanalysis.Index.FindSymbol",
		Source: "presence check mod/amqp.PlainAuth",
	})
}

func TestSequenceTrue(t *testing.T) {
	c := &domain.AnalysisCase{}
	usageCheck(c)
	c.EvidenceGraph.ModuleUsages = []domain.CallSite{
		{File: "cmd/app/main.go", Line: 10, Function: "main", Callee: "mod/amqp.URI.String"},
		{File: "cmd/app/main.go", Line: 20, Function: "main", Callee: "mod/amqp.ParseURI"},
	}
	claim := SymbolReachable{}.Evaluate(seqCond(), c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s: %s", claim.Result, claim.Explanation)
	}
	if len(claim.EvidenceIDs) == 0 {
		t.Fatal("TRUE must carry evidence")
	}
}

// Partial invocation through module internals also counts.
func TestSequenceTrueViaModuleChain(t *testing.T) {
	c := &domain.AnalysisCase{}
	usageCheck(c)
	c.EvidenceGraph.ModuleUsages = []domain.CallSite{
		{File: "cmd/app/main.go", Line: 10, Function: "main", Callee: "mod/amqp.URI.String"},
	}
	c.EvidenceGraph.ModuleReachable = map[string][]string{
		"mod/amqp.ParseURI": {"mod/amqp.URI.String", "mod/amqp.ParseURI"},
	}
	claim := SymbolReachable{}.Evaluate(seqCond(), c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s: %s", claim.Result, claim.Explanation)
	}
}

// GHSA-465g scenario: usage was checked, the pair is not exercised -> FALSE
// candidate (needs negative verification downstream).
func TestSequenceFalseCandidate(t *testing.T) {
	c := &domain.AnalysisCase{}
	usageCheck(c)
	c.EvidenceGraph.ModuleUsages = []domain.CallSite{
		{File: "cmd/app/main.go", Line: 10, Function: "main", Callee: "mod/amqp.Dial"},
	}
	claim := SymbolReachable{}.Evaluate(seqCond(), c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s: %s", claim.Result, claim.Explanation)
	}
}

func TestSequenceUnknownWhenUsageNeverChecked(t *testing.T) {
	claim := SymbolReachable{}.Evaluate(seqCond(), &domain.AnalysisCase{})
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN", claim.Result)
	}
}

func TestReadDirectionTrue(t *testing.T) {
	c := &domain.AnalysisCase{}
	readCheck(c)
	c.EvidenceGraph.AddSymbolRefs("mod/amqp.PlainAuth.Password",
		domain.CallSite{File: "cmd/app/main.go", Line: 42, Function: "main"})
	claim := SymbolReachable{}.Evaluate(readCond(), c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s: %s", claim.Result, claim.Explanation)
	}
}

// No product reader observed -> FALSE candidate, not silence.
func TestReadDirectionFalseCandidate(t *testing.T) {
	c := &domain.AnalysisCase{}
	readCheck(c)
	claim := SymbolReachable{}.Evaluate(readCond(), c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s: %s", claim.Result, claim.Explanation)
	}
}

func TestReadDirectionUnknownWhenUnscanned(t *testing.T) {
	claim := SymbolReachable{}.Evaluate(readCond(), &domain.AnalysisCase{})
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN", claim.Result)
	}
}

func TestPresenceTrue(t *testing.T) {
	c := &domain.AnalysisCase{}
	presenceCheck(c)
	c.EvidenceGraph.AddSymbolDecl("mod/amqp.PlainAuth",
		&domain.CallSite{File: "mod/amqp/auth.go", Line: 9})
	claim := Presence{}.Evaluate(presentCond(), c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s: %s", claim.Result, claim.Explanation)
	}
}

// Checked but absent (nil decl recorded) -> FALSE candidate.
func TestPresenceFalseCandidate(t *testing.T) {
	c := &domain.AnalysisCase{}
	presenceCheck(c)
	c.EvidenceGraph.AddSymbolDecl("mod/amqp.PlainAuth", nil)
	claim := Presence{}.Evaluate(presentCond(), c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s: %s", claim.Result, claim.Explanation)
	}
}

func TestPresenceUnknownWhenUnchecked(t *testing.T) {
	claim := Presence{}.Evaluate(presentCond(), &domain.AnalysisCase{})
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN", claim.Result)
	}
}

// Params select evaluators: Presence must claim presence conditions,
// SymbolReachable must claim both its param-directed branches.
func TestParamDispatch(t *testing.T) {
	if !(Presence{}).CanEvaluate(presentCond()) {
		t.Fatal("Presence must claim check=symbol_present")
	}
	if !(SymbolReachable{}).CanEvaluate(readCond()) || !(SymbolReachable{}).CanEvaluate(seqCond()) {
		t.Fatal("SymbolReachable must claim direction=read and sequence conditions")
	}
}
