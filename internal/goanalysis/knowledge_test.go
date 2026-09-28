package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

// The embedded defaults must parse, carry the shipped entries, and
// render back into a loadable extension file — `analyzer knowledge`
// output is a valid --knowledge template.
func TestDefaultKnowledgeEmbedded(t *testing.T) {
	kb := DefaultKnowledge()
	if kb.SourceFuncs["os.Getenv"] != domain.OriginConfiguration {
		t.Fatalf("os.Getenv=%q", kb.SourceFuncs["os.Getenv"])
	}
	if kb.SourceFuncs["net/http.Get"] != domain.OriginExternalUntrusted {
		t.Fatalf("net/http.Get=%q", kb.SourceFuncs["net/http.Get"])
	}
	if kb.ListenAddrArg["net.Listen"] != 1 || !slices.Contains(kb.ConfigTagKeys, "env") ||
		!slices.Contains(kb.DBPkgHints, "gorm") || !kb.AuthCallNames["SetBasicAuth"] {
		t.Fatal("embedded defaults missing expected entries")
	}

	b, err := json.Marshal(kb.AsFile())
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseKnowledgeFile(bytes.NewReader(b))
	if err != nil {
		t.Fatalf("AsFile output must parse: %v", err)
	}
	if len(f.SourceFuncs) != len(kb.SourceFuncs) || len(f.ListenerPrimitives) != len(kb.ListenerPrimitives) {
		t.Fatal("AsFile round-trip lost entries")
	}
	// A file built on the dump merges back cleanly — same-value repeats
	// are no-ops, only rewrites conflict.
	if err := DefaultKnowledge().Merge(f); err != nil {
		t.Fatalf("dump re-merge must be a no-op: %v", err)
	}
}

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

// Merges are additive only: re-declaring an entry with a different
// value is a conflict error, never a silent override.
func TestKnowledgeMergeConflicts(t *testing.T) {
	kb := DefaultKnowledge()
	for _, f := range []KnowledgeFile{
		{SourceFuncs: map[string]string{"os.Getenv": "DATABASE"}},
		{PassthroughFuncs: map[string]int{"io.ReadAll": 1}},
		{ListenAddrArg: map[string]int{"net.Listen": 0}},
	} {
		if err := kb.Merge(f); err == nil || !strings.Contains(err.Error(), "refusing to override") {
			t.Fatalf("expected conflict for %+v, got %v", f, err)
		}
	}
}
