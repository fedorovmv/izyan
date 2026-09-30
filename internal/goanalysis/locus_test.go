package goanalysis

import (
	"context"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

// SymbolFaultingUse separates the defect site (body indexes the guarded
// value) from an upstream enabler (body only validates it).
func TestSymbolFaultingUse(t *testing.T) {
	ix := fixture(t, "locusprod")
	ctx := context.Background()
	pkg := "example.com/locusprod"

	for _, tc := range []struct {
		name     string
		symbol   string
		operands []string
		want     bool
	}{
		{"indexing guarded slice", "defectSite", []string{"authority"}, true},
		{"validation only", "enabler", []string{`mdata[":authority"]`}, false},
		{"aliased operand indexed", "aliasedDefect", []string{`mdata[":authority"]`}, true},
		{"method receiver qualified", "server.method", []string{"authority"}, true},
		{"unrelated operand", "defectSite", []string{"unrelated"}, false},
	} {
		got, err := ix.SymbolFaultingUse(ctx, domain.SymbolRef{Package: pkg, Symbol: tc.symbol}, tc.operands)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// An unresolvable symbol is an error — callers keep the candidate in the
// locus set rather than excluding it on a failed check.
func TestSymbolFaultingUseUnresolved(t *testing.T) {
	ix := fixture(t, "locusprod")
	_, err := ix.SymbolFaultingUse(context.Background(),
		domain.SymbolRef{Package: "example.com/locusprod", Symbol: "Missing"}, []string{"x"})
	if err == nil {
		t.Fatal("expected error for missing symbol")
	}
}
