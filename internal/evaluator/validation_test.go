package evaluator

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
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

func TestAttackerControlConstantInputHasFalsifier(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{
		ConditionID: "C-INPUT", Origin: domain.OriginConstant,
		Sink: domain.CallSite{File: "a.go", Line: 10}, Arg: 0,
	}}
	claim := ArgumentOrigin{}.Evaluate(domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 0,
	}, c)
	if claim.Result != domain.ClaimFalse || claim.Falsifier == "" {
		t.Fatalf("constant input claim=%+v; want FALSE with falsifier", claim)
	}
}

func TestAttackerControlEmptyOriginCannotFalsify(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{
		ConditionID: "C-INPUT", Sink: domain.CallSite{File: "a.go", Line: 10}, Arg: 0,
	}}
	claim := ArgumentOrigin{}.Evaluate(domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 0,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("missing origin claim=%+v; want UNKNOWN", claim)
	}
}
