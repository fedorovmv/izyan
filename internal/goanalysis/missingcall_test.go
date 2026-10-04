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

	omitted, content, callers, err := ix.CheckMissingCall(context.Background(), check, pipeline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !omitted {
		t.Fatalf("expected omitted = true, got false; content: %s", content)
	}
	if len(callers) == 0 {
		t.Fatalf("expected at least 1 caller reaching pipeline, got 0")
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

	omitted, content, _, err := ix.CheckMissingCall(context.Background(), check, pipeline)
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

	omitted, content, _, err := ix.CheckMissingCall(context.Background(), check, pipeline)
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

func TestCheckMissingCall_PipelineDeclNotFound(t *testing.T) {
	ix := fixture(t, "ifaceprod")
	check := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.VerifyAudience"}
	// fmt.Stringer.String is reached as an interface call, but has no ast.FuncDecl in AST.
	pipeline := domain.SymbolRef{Package: "fmt", Symbol: "Stringer.String"}

	omitted, content, _, err := ix.CheckMissingCall(context.Background(), check, pipeline)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if omitted {
		t.Fatalf("expected omitted = false when pipeline decl is not found, got true; content: %s", content)
	}
	if !strings.Contains(content, "declaration Stringer.String not found") && !strings.Contains(content, "cannot inspect pipeline") {
		t.Fatalf("expected content to explain declaration not found: %s", content)
	}
}

func TestFindFuncDecl(t *testing.T) {
	ix := fixture(t, "missingcall")
	if _, err := ix.loadExtra(context.Background(), "example.com/dep/vuln"); err != nil {
		t.Fatalf("loadExtra failed: %v", err)
	}
	pkgs := ix.extrasFor("example.com/dep/vuln")
	pkg, fn := findFuncDecl(pkgs, domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.Valid"})
	if pkg == nil || fn == nil {
		t.Fatalf("expected to find MapClaims.Valid, got nil")
	}

	pkgNone, fnNone := findFuncDecl(pkgs, domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "MapClaims.NonExistent"})
	if fnNone != nil || pkgNone != nil {
		t.Fatalf("expected nil for non-existent method, got pkg=%v, fn=%v", pkgNone, fnNone)
	}
}
