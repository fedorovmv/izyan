package evaluator

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestValidationFalseWhenAllGuarded(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{
		{ConditionID: "C-V", Sink: domain.CallSite{File: "a.go", Line: 40}},
		{ConditionID: "C-V", Sink: domain.CallSite{File: "b.go", Line: 20}},
	}
	c.EvidenceGraph.Validations = []domain.Validation{
		{CallSite: domain.CallSite{File: "a.go", Line: 30}},
		{CallSite: domain.CallSite{File: "b.go", Line: 10}},
	}
	cl := Validation{}.Evaluate(domain.Condition{ID: "C-V", Kind: domain.ConditionValidation}, c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("result=%s want FALSE", cl.Result)
	}
}

func TestValidationUnknownOnPartialCoverage(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{
		{ConditionID: "C-V", Sink: domain.CallSite{File: "a.go", Line: 40}},
		{ConditionID: "C-V", Sink: domain.CallSite{File: "b.go", Line: 20}},
	}
	c.EvidenceGraph.Validations = []domain.Validation{
		{CallSite: domain.CallSite{File: "a.go", Line: 30}},
	}
	cl := Validation{}.Evaluate(domain.Condition{ID: "C-V", Kind: domain.ConditionValidation}, c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s want UNKNOWN", cl.Result)
	}
}

func TestValidationUnknownNoFlows(t *testing.T) {
	cl := Validation{}.Evaluate(
		domain.Condition{ID: "C-V", Kind: domain.ConditionValidation},
		&domain.AnalysisCase{})
	if cl.Result != domain.ClaimUnknown || len(cl.Limitations) == 0 {
		t.Fatalf("claim=%+v", cl)
	}
}

func TestInputConstraintFalseWhenAllBounded(t *testing.T) {
	sink := domain.CallSite{File: "a.go", Line: 40}
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{
		{ConditionID: "C-C", Sink: sink, Origin: domain.OriginConfiguration},
	}
	c.EvidenceGraph.Validations = []domain.Validation{
		{CallSite: sink, Guard: true, Covers: &sink,
			Property: "every write site of field n stores a bounded value"},
	}
	cl := ArgumentOrigin{}.Evaluate(
		domain.Condition{ID: "C-C", Kind: domain.ConditionInputConstraint}, c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("result=%s want FALSE (all bounded): %s", cl.Result, cl.Explanation)
	}
}

func TestInputConstraintUnknownWithUnresolvedOrigin(t *testing.T) {
	sink := domain.CallSite{File: "a.go", Line: 40}
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{
		{ConditionID: "C-C", Sink: sink, Origin: domain.OriginConfiguration},
		{ConditionID: "C-C", Sink: sink, Origin: domain.OriginUnknown},
	}
	c.EvidenceGraph.Validations = []domain.Validation{
		{CallSite: sink, Guard: true, Covers: &sink},
	}
	cl := ArgumentOrigin{}.Evaluate(
		domain.Condition{ID: "C-C", Kind: domain.ConditionInputConstraint}, c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s want UNKNOWN (one origin unresolved)", cl.Result)
	}
}
