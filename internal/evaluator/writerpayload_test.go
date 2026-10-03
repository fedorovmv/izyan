package evaluator

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestUnboundedWriterOriginRemainsUnknown(t *testing.T) {
	flow := domain.DataFlow{
		ConditionID:     "C-INPUT",
		Arg:             0,
		Origin:          domain.OriginExternalUntrusted,
		PayloadUnproven: true,
		Sink:            domain.CallSite{File: "a.go", Line: 10},
	}
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{flow}
	claim := ArgumentOrigin{}.Evaluate(domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: -1,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("writer-only external origin claim=%+v; want UNKNOWN", claim)
	}
	if !strings.Contains(strings.Join(claim.Limitations, " "), "outbound writer capability alone does not establish payload at an unspecified argument index") {
		t.Fatalf("claim lacks writer payload limitation: %+v", claim.Limitations)
	}
}

func TestUnprovenPayloadDoesNotTreatUnknownOriginAsEvidence(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{
		ConditionID:     "C-INPUT",
		Arg:             0,
		Origin:          domain.OriginUnknown,
		PayloadUnproven: true,
		Sink:            domain.CallSite{File: "a.go", Line: 10},
	}}
	claim := ArgumentOrigin{}.Evaluate(domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: -1,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("unknown writer origin claim=%+v; want UNKNOWN", claim)
	}
}

func TestWriterFlagDoesNotHideExternalOriginFromExplicitPayloadIndex(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{
		ConditionID:     "C-INPUT",
		Arg:             0,
		Origin:          domain.OriginExternalUntrusted,
		PayloadUnproven: true,
		Sink:            domain.CallSite{File: "a.go", Line: 10},
	}}
	claim := ArgumentOrigin{}.Evaluate(domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: 0,
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("bounded external writer origin claim=%+v; want TRUE", claim)
	}
}

func TestWriterOriginWithOtherPayloadFlows(t *testing.T) {
	for _, kind := range []domain.ConditionKind{
		domain.ConditionAttackerControl,
		domain.ConditionInputConstraint,
	} {
		for _, tc := range []struct {
			name  string
			flows []domain.DataFlow
			want  domain.ClaimResult
		}{
			{
				name: "unresolved payload",
				flows: []domain.DataFlow{
					{Origin: domain.OriginExternalUntrusted, PayloadUnproven: true},
					{Origin: domain.OriginUnknown},
				},
				want: domain.ClaimUnknown,
			},
			{
				name: "constant alongside writer",
				flows: []domain.DataFlow{
					{Origin: domain.OriginExternalUntrusted, PayloadUnproven: true},
					{Origin: domain.OriginConstant},
				},
				want: domain.ClaimUnknown,
			},
			{
				name: "external payload alongside writer",
				flows: []domain.DataFlow{
					{Origin: domain.OriginExternalUntrusted, PayloadUnproven: true},
					{Origin: domain.OriginExternalUntrusted},
				},
				want: domain.ClaimTrue,
			},
		} {
			t.Run(string(kind)+"/"+tc.name, func(t *testing.T) {
				c := &domain.AnalysisCase{}
				for i := range tc.flows {
					tc.flows[i].ConditionID = "C-INPUT"
					tc.flows[i].Arg = i
				}
				c.EvidenceGraph.DataFlows = tc.flows
				claim := ArgumentOrigin{}.Evaluate(domain.Condition{
					ID: "C-INPUT", Kind: kind, ArgIndex: -1,
				}, c)
				if claim.Result != tc.want {
					t.Fatalf("claim=%+v; want %s", claim, tc.want)
				}
			})
		}
	}
}

func TestUnprovenWriterOriginBlocksGuardBasedFalse(t *testing.T) {
	sink := domain.CallSite{File: "a.go", Line: 20}
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{
		ConditionID:     "C-INPUT",
		Arg:             0,
		Origin:          domain.OriginExternalUntrusted,
		PayloadUnproven: true,
		Sink:            sink,
	}}
	c.EvidenceGraph.Validations = []domain.Validation{{
		CallSite: domain.CallSite{File: "a.go", Line: 10},
		Guard:    true,
		Covers:   &sink,
	}}
	claim := ArgumentOrigin{}.Evaluate(domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionInputConstraint, ArgIndex: -1,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("guarded writer flow claim=%+v; unproven payload must block FALSE", claim)
	}
}

func TestUnmarkedExternalPayloadStillProvesAttackerControl(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.DataFlows = []domain.DataFlow{{
		ConditionID: "C-INPUT",
		Arg:         0,
		Origin:      domain.OriginExternalUntrusted,
		Sink:        domain.CallSite{File: "a.go", Line: 10},
	}}
	claim := ArgumentOrigin{}.Evaluate(domain.Condition{
		ID: "C-INPUT", Kind: domain.ConditionAttackerControl, ArgIndex: -1,
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("external payload claim=%+v; want TRUE", claim)
	}
}
