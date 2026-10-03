package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
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
		if strings.Contains(lim, "widens the call graph") {
			t.Fatalf("unexpected reflect call-graph limitation for standalone function: %s", lim)
		}
	}

	// 2. Exported method on a type: reflect method call DOES add call-graph limitation
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
			if strings.Contains(lim, "widens the call graph") {
				hasReflectLim = true
				break
			}
		}
	}
	if !hasReflectLim {
		t.Fatalf("expected reflect call-graph limitation for exported method, got nv=%+v", out2.NegativeVerification)
	}
}

func TestGovulncheckSilenceWithUnexportedSubject(t *testing.T) {
	ix := fixture(t, "constprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}

	unexportedSym := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "internalHelper"}

	// 1. With FalsifierGovulncheckSilence and no live dep callers: verified
	claim1 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierGovulncheckSilence,
	}
	cond1 := domain.Condition{
		ID:       "C-REACH",
		Kind:     domain.ConditionSymbolReachable,
		Subjects: []domain.SymbolRef{unexportedSym},
	}
	out1 := v.VerifyFalse(context.Background(), c, claim1, cond1)
	if out1.NegativeVerification == nil || out1.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for govulncheck silence with unexported symbol, got: %+v", out1.NegativeVerification)
	}

	// 2. With FalsifierUnreachedExportedSubject: insufficient scope because visibility forces zero refs
	claim2 := domain.Claim{
		ConditionID: "C-REACH",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierUnreachedExportedSubject,
	}
	out2 := v.VerifyFalse(context.Background(), c, claim2, cond1)
	if out2.NegativeVerification == nil || out2.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("expected NegativeInsufficientScope for no-product-refs on unexported symbol, got: %+v", out2.NegativeVerification)
	}
}

func TestVerifyInputFalse_ConstantPayloadVerified(t *testing.T) {
	ix := fixture(t, "constprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "gopkg.in/yaml.v2"},
	}
	subject := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{subject},
		ArgIndex: 0,
	}
	claim := domain.Claim{
		ConditionID: "C-INPUT",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierConstantOrGeneratedInput,
	}

	out := v.VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for constant payload, got: %+v", out.NegativeVerification)
	}
	if !strings.Contains(out.NegativeVerification.Notes, "pass verified constant or generated payload") {
		t.Fatalf("unexpected notes: %q", out.NegativeVerification.Notes)
	}
}

func TestVerifyInputFalse_TrustedConfigVerified(t *testing.T) {
	ix := fixture(t, "fieldprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "example.com/dep"},
	}
	subject := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{subject},
		ArgIndex: 0,
	}
	claim := domain.Claim{
		ConditionID: "C-INPUT",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierTrustedInfrastructure,
	}

	out := v.VerifyFalse(context.Background(), c, claim, cond)
	if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified for trusted config, got: %+v", out.NegativeVerification)
	}
	if !strings.Contains(out.NegativeVerification.Notes, "consume local configuration files (trusted infrastructure)") {
		t.Fatalf("unexpected notes: %q", out.NegativeVerification.Notes)
	}
}

func TestVerifyInputFalse_ExternalInputContradictsConstantAndConfig(t *testing.T) {
	ix := fixture(t, "extprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{Module: "example.com/dep"},
	}
	subject := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}
	cond := domain.Condition{
		ID:       "C-INPUT",
		Kind:     domain.ConditionAttackerControl,
		Subjects: []domain.SymbolRef{subject},
		ArgIndex: 0,
	}

	for _, falsifier := range []string{domain.FalsifierConstantOrGeneratedInput, domain.FalsifierTrustedInfrastructure} {
		claim := domain.Claim{
			ConditionID: "C-INPUT",
			Result:      domain.ClaimFalse,
			Falsifier:   falsifier,
		}
		out := v.VerifyFalse(context.Background(), c, claim, cond)
		if out.NegativeVerification == nil || out.NegativeVerification.Status != domain.NegativeContradicted {
			t.Fatalf("falsifier %q: expected NegativeContradicted for external input, got: %+v", falsifier, out.NegativeVerification)
		}
	}
}
