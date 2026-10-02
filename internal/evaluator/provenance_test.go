package evaluator

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestArgumentOrigin_ConstantPayloadSurvivesIncompleteClosure(t *testing.T) {
	ao := ArgumentOrigin{}
	cond := domain.Condition{
		ID:       "C-PEER-INPUT",
		Kind:     domain.ConditionAttackerControl,
		ArgIndex: -1,
		Params:   map[string]string{domain.ParamInputSource: "peer"},
	}
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "gopkg.in/yaml.v2"},
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{
				{
					ConditionID:     cond.ID,
					Arg:             0,
					Origin:          domain.OriginConstant,
					Summary:         "const baseline",
					PayloadUnproven: false,
					Sink: domain.CallSite{
						Package:  "example.com/product",
						Function: "load",
						File:     "main.go",
						Line:     26,
					},
				},
			},
			Evidence: []domain.Evidence{
				{
					ID:   "DF-01",
					Kind: domain.EvidenceDataFlow,
				},
			},
			// Ingress closure with unresolved internal parser items
			IngressClosures: []domain.IngressClosure{
				{
					ConditionID: "C-PEER-INPUT",
					Module:      "gopkg.in/yaml.v2",
					Complete:    false,
					Blockers:    []string{"unmodeled external call"},
				},
			},
		},
	}

	claim := ao.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("expected ClaimFalse for constant payload, got %s (limitations: %v)", claim.Result, claim.Limitations)
	}
	if claim.Falsifier != domain.FalsifierConstantOrGeneratedInput {
		t.Fatalf("expected FalsifierConstantOrGeneratedInput, got %s", claim.Falsifier)
	}
}

func TestArgumentOrigin_LocalConfigurationTrusted(t *testing.T) {
	ao := ArgumentOrigin{}
	cond := domain.Condition{
		ID:       "C-PEER-INPUT",
		Kind:     domain.ConditionAttackerControl,
		ArgIndex: -1,
		Params:   map[string]string{domain.ParamInputSource: "peer"},
	}
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "gopkg.in/yaml.v2"},
		EvidenceGraph: domain.EvidenceGraph{
			DataFlows: []domain.DataFlow{
				{
					ConditionID:     cond.ID,
					Arg:             0,
					Origin:          domain.OriginConfiguration,
					Summary:         "os.ReadFile",
					PayloadUnproven: false,
					Sink: domain.CallSite{
						Package:  "example.com/product",
						Function: "load",
						File:     "main.go",
						Line:     28,
					},
				},
			},
			Evidence: []domain.Evidence{
				{
					ID:   "DF-01",
					Kind: domain.EvidenceDataFlow,
				},
			},
		},
	}

	claim := ao.Evaluate(cond, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("expected ClaimFalse for local config file, got %s (limitations: %v)", claim.Result, claim.Limitations)
	}
	if claim.Falsifier != domain.FalsifierTrustedInfrastructure {
		t.Fatalf("expected FalsifierTrustedInfrastructure, got %s", claim.Falsifier)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified on ClaimFalse, got %+v", claim.NegativeVerification)
	}
}
