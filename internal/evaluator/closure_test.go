package evaluator

import (
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestIngressClosureDoesNotExcludeUnconnectedInputs(t *testing.T) {
	for _, origin := range []domain.DataOrigin{domain.OriginUnknown, domain.OriginExternalUntrusted, domain.OriginConfiguration} {
		t.Run(string(origin), func(t *testing.T) {
			cond := domain.Condition{ID: "C-INPUT", Kind: domain.ConditionAttackerControl}
			c := &domain.AnalysisCase{}
			c.Vulnerability.Module = "example.com/dep"
			c.EvidenceGraph.DataFlows = []domain.DataFlow{{ConditionID: cond.ID, Origin: domain.OriginConstant}}
			c.EvidenceGraph.AddIngressClosure(domain.IngressClosure{
				ConditionID: cond.ID, Module: c.Vulnerability.Module, Complete: true,
				Items: []domain.IngressItem{{Kind: domain.IngressBoundaryArg, Origin: origin}},
			})
			claim := (ArgumentOrigin{}).Evaluate(cond, c)
			if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
				t.Fatalf("unproven nonpayload input authorized negative: %+v", claim)
			}
		})
	}
}

func TestUnresolvedDependencyFlowCannotUseGuards(t *testing.T) {
	cond := domain.Condition{ID: "C", Kind: domain.ConditionInputConstraint, ArgIndex: 0}
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep"
	site := domain.CallSite{File: "dep.go", Line: 8, Package: "example.com/dep/vuln"}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{ConditionID: cond.ID, Sink: site, Arg: 0, Origin: domain.OriginUnknown}}
	c.EvidenceGraph.Validations = []domain.Validation{{Guard: true, Covers: &site, Arg: 0}}
	c.EvidenceGraph.AddIngressClosure(domain.IngressClosure{ConditionID: cond.ID, Module: c.Vulnerability.Module})
	claim := (ArgumentOrigin{}).Evaluate(cond, c)
	if claim.Result != domain.ClaimUnknown || claim.Falsifier != "" {
		t.Fatalf("unresolved dependency flow was falsified by guards: %+v", claim)
	}
}
