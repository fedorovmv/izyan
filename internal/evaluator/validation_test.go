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
