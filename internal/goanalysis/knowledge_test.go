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

	"github.com/fedorovmv/izyan/internal/domain"
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
	if f.SchemaVersion != KnowledgeSchemaVersion || f.Language != "go" {
		t.Fatalf("dump meta schema_version=%d language=%q", f.SchemaVersion, f.Language)
	}
	// name/labels are informational — they must not break parsing.
	if _, err := parseKnowledgeFile(strings.NewReader(
		`{"name": "corp", "labels": ["org", "internal"], "source_funcs": {}}`)); err != nil {
		t.Fatalf("meta labels rejected: %v", err)
	}
	// A file built on the dump merges back cleanly — same-value repeats
	// are no-ops, only rewrites conflict.
	if err := DefaultKnowledge().Merge(f); err != nil {
		t.Fatalf("dump re-merge must be a no-op: %v", err)
	}
}

// The digest pins the effective content for reports: deterministic for
// the same tables, changed by any merged entry; Sources name the files
// that contributed.
func TestKnowledgeProvenance(t *testing.T) {
	base := DefaultKnowledge()
	if !slices.Contains(base.Sources, "builtin@2026-09-30") {
		t.Fatalf("sources=%v", base.Sources)
	}
	d1 := base.Digest()
	if !strings.HasPrefix(d1, "sha256:") || len(d1) != len("sha256:")+64 {
		t.Fatalf("digest=%q", d1)
	}
	if d2 := DefaultKnowledge().Digest(); d2 != d1 {
		t.Fatalf("digest not deterministic: %s vs %s", d1, d2)
	}
	f, err := LoadKnowledgeFile(writeKnowledge(t,
		`{"name": "corp", "data_version": "2026-10-01", "source_funcs": {"x.Y": "DATABASE"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := base.Merge(f); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(base.Sources, "corp@2026-10-01") {
		t.Fatalf("sources=%v", base.Sources)
	}
	if base.Digest() == d1 {
		t.Fatal("merge must change the digest")
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
		{"future version", `{"schema_version": 99}`, "unsupported knowledge schema version"},
		// A newer schema's fields must surface as a version error, not
		// a misleading unknown-field one.
		{"future schema fields", `{"schema_version": 4, "java": {}}`, "unsupported knowledge schema version"},
		{"negative version", `{"schema_version": -1}`, "unsupported knowledge schema version"},
		{"wrong language", `{"language": "java"}`, `targets language "java"`},
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
