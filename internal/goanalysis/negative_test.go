package goanalysis

import (
	"context"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestSymbolIsMethod(t *testing.T) {
	cases := []struct {
		sym  domain.SymbolRef
		want bool
	}{
		{domain.SymbolRef{Package: "example.com/dep/s2", Symbol: "NewDict"}, false},
		{domain.SymbolRef{Package: "golang.org/x/crypto/ssh", Symbol: "NewServerConn"}, false},
		{domain.SymbolRef{Package: "github.com/valyala/fasthttp", Symbol: "ServeFile"}, false},
		{domain.SymbolRef{Package: "example.com/dep", Symbol: "Server.Serve"}, true},
		{domain.SymbolRef{Package: "example.com/dep", Symbol: "(*Server).Serve"}, true},
	}
	for _, tc := range cases {
		if got := symbolIsMethod(tc.sym); got != tc.want {
			t.Errorf("symbolIsMethod(%+v) = %v, want %v", tc.sym, got, tc.want)
		}
	}
}

func TestReflectMarkerStandaloneFunctionScoping(t *testing.T) {
	ix := fixture(t, "reflectprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep"

	// 1. Standalone function: reflect import does NOT widen call graph
	standaloneSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "NewDict"}
	claim1 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond1 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{standaloneSym},
	}

	out1 := v.VerifyFalse(context.Background(), c, claim1, cond1)
	if out1.NegativeVerification == nil || out1.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for standalone function, got: %+v", out1.NegativeVerification)
	}
	for _, lim := range out1.NegativeVerification.Limitations {
		if strings.Contains(lim, "reflect usage in product widens the call graph") {
			t.Fatalf("unexpected reflect call-graph limitation for standalone function: %s", lim)
		}
	}

	// 2. Exported method on a type: reflect import DOES add call-graph limitation
	methodSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Server.Serve"}
	claim2 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond2 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{methodSym},
	}

	out2 := v.VerifyFalse(context.Background(), c, claim2, cond2)
	hasReflectLim := false
	if out2.NegativeVerification != nil {
		for _, lim := range out2.NegativeVerification.Limitations {
			if strings.Contains(lim, "reflect usage in product widens the call graph") {
				hasReflectLim = true
				break
			}
		}
	}
	if !hasReflectLim {
		t.Fatalf("expected reflect call-graph limitation for exported method, got nv=%+v", out2.NegativeVerification)
	}
}
