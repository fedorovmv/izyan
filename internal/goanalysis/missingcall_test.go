package goanalysis

import (
	"context"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestCheckMissingCall_Omitted(t *testing.T) {
	ix := fixture(t, "missingcall")
	check := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"}
	pipeline := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.Valid"}

	omitted, content, err := ix.CheckMissingCall(context.Background(), check, pipeline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !omitted {
		t.Fatalf("expected omitted = true, got false; content: %s", content)
	}
	if !strings.Contains(content, "MapClaims.VerifyAudience") || !strings.Contains(content, "MapClaims.Valid") {
		t.Fatalf("content missing symbols: %s", content)
	}
	if !strings.Contains(content, "0") {
		t.Fatalf("content should mention 0 invocations: %s", content)
	}
}

func TestCheckMissingCall_ExplicitlyInvoked(t *testing.T) {
	ix := fixture(t, "missingcallinvoked")
	check := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"}
	pipeline := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.Valid"}

	omitted, content, err := ix.CheckMissingCall(context.Background(), check, pipeline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if omitted {
		t.Fatalf("expected omitted = false when check is invoked in product code, got true; content: %s", content)
	}
	if !strings.Contains(content, "invoked") {
		t.Fatalf("expected content to explain check was invoked: %s", content)
	}
}

func TestCheckMissingCall_PipelineNotReached(t *testing.T) {
	ix := fixture(t, "constprod")
	check := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"}
	pipeline := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.Valid"}

	omitted, content, err := ix.CheckMissingCall(context.Background(), check, pipeline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if omitted {
		t.Fatalf("expected omitted = false when pipeline is not reached, got true; content: %s", content)
	}
	if !strings.Contains(content, "not reached") {
		t.Fatalf("expected content to explain pipeline was not reached: %s", content)
	}
}
