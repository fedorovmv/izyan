package tracker

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Ticket is the generic tracker-intake format: a minimal JSON document a
// ticket pipeline can emit to feed an analysis without any proprietary
// tracker coupling (spec §25 generic integration points).
//
// Fields, all optional except a vulnerability reference:
//
//	{
//	  "id": "TEAM-1234",                     // external ticket id (metadata only)
//	  "vulnerability": "GHSA-xxxx-yyyy-zzzz",// GO-/CVE-/GHSA id to analyze
//	  "repo": "/path/to/product",            // product checkout override
//	  "module": "github.com/x/y",            // fallback module when no OSV doc
//	  "imports": ["github.com/x/y/pkg"],     // vulnerable packages (default: module)
//	  "symbols": ["pkg/path.Sym"],           // optional affected symbols
//	  "fixed_versions": ["v1.2.3"],          // synthesized advisory range
//	  "osv": { ... }                         // embedded OSV advisory document
//	}
type Ticket struct {
	ID            string          `json:"id"`
	Vulnerability string          `json:"vulnerability"`
	Repo          string          `json:"repo,omitempty"`
	Module        string          `json:"module,omitempty"`
	Imports       []string        `json:"imports,omitempty"`
	Symbols       []string        `json:"symbols,omitempty"`
	FixedVersions []string        `json:"fixed_versions,omitempty"`
	OSV           json.RawMessage `json:"osv,omitempty"`
}

// LoadTicket parses a ticket JSON file.
func LoadTicket(path string) (*Ticket, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var t Ticket
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("ticket %s: %w", path, err)
	}
	return &t, nil
}

// AdvisoryFile materializes the ticket's advisory data as an OSV JSON
// file the analyzer can consume: the embedded "osv" document verbatim,
// or a minimal synthesized doc from module+fixed_versions. Returns ""
// when the ticket carries no advisory material (the caller falls back
// to the configured vulnerability source).
func (t *Ticket) AdvisoryFile(dir, vulnID string) (string, error) {
	var doc []byte
	switch {
	case len(t.OSV) > 0:
		doc = t.OSV
	case t.Module != "":
		imports := t.Imports
		if len(imports) == 0 {
			imports = []string{t.Module}
		}
		var imps []map[string]any
		for _, p := range imports {
			imp := map[string]any{"path": p}
			if syms := t.symbolsFor(p); len(syms) > 0 {
				imp["symbols"] = syms
			}
			imps = append(imps, imp)
		}
		synth := map[string]any{
			"id": vulnID,
			"affected": []map[string]any{{
				"package": map[string]any{"ecosystem": "Go", "name": t.Module},
				"ranges": []map[string]any{{
					"type":   "SEMVER",
					"events": ticketEvents(t.FixedVersions),
				}},
				"ecosystem_specific": map[string]any{"imports": imps},
			}},
		}
		b, err := json.Marshal(synth)
		if err != nil {
			return "", err
		}
		doc = b
	default:
		return "", nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, "ticket-advisory.json")
	if err := os.WriteFile(p, doc, 0o644); err != nil {
		return "", err
	}
	return p, nil
}

// ticketEvents builds SEMVER range events: introduced at 0, each fixed
// version in listed order. No fixed version = open-ended range.
func ticketEvents(fixed []string) []map[string]string {
	ev := []map[string]string{{"introduced": "0"}}
	for _, f := range fixed {
		ev = append(ev, map[string]string{"fixed": f})
	}
	return ev
}

// symbolsFor returns the ticket's symbol entries scoped to package p —
// symbols are given as "pkg/path.Symbol"; entries whose package matches
// p contribute their bare symbol name, unqualified entries apply to all.
func (t *Ticket) symbolsFor(p string) []string {
	var out []string
	for _, s := range t.Symbols {
		i := strings.LastIndex(s, ".")
		if i <= 0 {
			out = append(out, s)
			continue
		}
		if s[:i] == p {
			out = append(out, s[i+1:])
		}
	}
	return out
}
