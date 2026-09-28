package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func writeKnowledge(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "knowledge.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// A --knowledge extension names the product-local config getter as a
// CONFIGURATION source: the argument trace resolves where the default
// knowledge base leaves it UNKNOWN.
func TestKnowledgeExtendSourceFuncs(t *testing.T) {
	ix := fixture(t, "kbprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginUnknown {
		t.Fatalf("default origin=%s want UNKNOWN (%s)", flow.Origin, flow.Summary)
	}

	f, err := LoadKnowledgeFile(writeKnowledge(t,
		`{"source_funcs": {"example.com/kbprod/kv.Get": "CONFIGURATION"}}`))
	if err != nil {
		t.Fatal(err)
	}
	kb := DefaultKnowledge()
	if err := kb.Merge(f); err != nil {
		t.Fatal(err)
	}
	ix2 := fixture(t, "kbprod")
	ix2.KB = kb
	flow2, _, err := ix2.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow2.Origin != domain.OriginConfiguration {
		t.Fatalf("extended origin=%s want CONFIGURATION (%s)", flow2.Origin, flow2.Summary)
	}
}

func TestKnowledgeFileValidation(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"unknown key", `{"source_funcz": {}}`, "unknown field"},
		{"bad origin", `{"source_funcs": {"x.Y": "TRUSTED"}}`, "unknown data origin"},
		{"negative passthrough", `{"passthrough_funcs": {"x.Y": -1}}`, "negative"},
		{"negative populate dst", `{"slice_populate_funcs": {"x.Y": [-1, 0]}}`, "negative"},
		{"false member", `{"auth_call_names": {"X": false}}`, "must be true"},
		{"bad listen index", `{"listen_addr_arg": {"x.Y": -2}}`, "below -1"},
		{"incomplete primitive", `{"listener_primitives": [{"package": "net"}]}`, "package and symbol"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadKnowledgeFile(writeKnowledge(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want substring %q", err, tc.want)
			}
		})
	}
}

// Merges are additive only: a key the base already defines is a conflict
// error, never a silent override.
func TestKnowledgeMergeConflicts(t *testing.T) {
	kb := DefaultKnowledge()
	for _, f := range []KnowledgeFile{
		{SourceFuncs: map[string]string{"os.Getenv": "CONFIGURATION"}},
		{ConfigTagKeys: []string{"env"}},
		{AuthCallNames: map[string]bool{"SetBasicAuth": true}},
		{ListenAddrArg: map[string]int{"net.Listen": 0}},
		{ListenerPrimitives: []domain.SymbolRef{{Package: "net", Symbol: "Listen"}}},
		{DBPkgHints: []string{"gorm"}},
	} {
		if err := kb.Merge(f); err == nil || !strings.Contains(err.Error(), "already defined") {
			t.Fatalf("expected conflict for %+v, got %v", f, err)
		}
	}
}
