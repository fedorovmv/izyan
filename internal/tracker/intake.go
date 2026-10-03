package tracker

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Ticket is the generic tracker-intake format: a structured record or parsed ticket
// containing vulnerability and product snapshot metadata.
type Ticket struct {
	ID            string          `json:"id,omitempty"`
	Vulnerability string          `json:"vulnerability,omitempty"`
	Aliases       []string        `json:"aliases,omitempty"`
	Repo          string          `json:"repo,omitempty"`
	Module        string          `json:"module,omitempty"`
	Package       string          `json:"package,omitempty"`
	Imports       []string        `json:"imports,omitempty"`
	Symbols       []string        `json:"symbols,omitempty"`
	Version       string          `json:"version,omitempty"`
	FixedVersions []string        `json:"fixed_versions,omitempty"`
	Component     string          `json:"component,omitempty"`
	Product       string          `json:"product,omitempty"`
	Release       string          `json:"release,omitempty"`
	Summary       string          `json:"summary,omitempty"`
	Description   string          `json:"description,omitempty"`
	Rationale     string          `json:"rationale,omitempty"`
	OSV           json.RawMessage `json:"osv,omitempty"`
}

// LoadTicket parses a ticket from a JSON file, arbitrary text file, or stdin (when path is "-").
func LoadTicket(path string) (*Ticket, error) {
	return LoadTicketWithID(path, "")
}

// LoadTicketWithID parses tickets from a file or stdin, optionally selecting by ticket ID.
func LoadTicketWithID(path, targetID string) (*Ticket, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(os.Stdin)
	} else {
		b, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read ticket %s: %w", path, err)
	}

	tickets, err := ParseTickets(b)
	if err != nil {
		return nil, fmt.Errorf("ticket %s: %w", path, err)
	}
	if len(tickets) == 0 {
		return nil, fmt.Errorf("ticket %s: no tickets found", path)
	}

	if targetID != "" {
		for _, t := range tickets {
			if strings.EqualFold(t.ID, targetID) {
				return t, nil
			}
		}
		var found []string
		for _, t := range tickets {
			if t.ID != "" {
				found = append(found, t.ID)
			}
		}
		return nil, fmt.Errorf("ticket %q not found in %s (found: %s)", targetID, path, strings.Join(found, ", "))
	}

	return tickets[0], nil
}

// ParseTicket parses a single ticket from JSON or raw text.
func ParseTicket(data []byte) (*Ticket, error) {
	tickets, err := ParseTickets(data)
	if err != nil {
		return nil, err
	}
	if len(tickets) == 0 {
		return nil, fmt.Errorf("no ticket parsed from input")
	}
	return tickets[0], nil
}

// ParseTickets parses data as either a JSON array of tickets, a single JSON ticket,
// or arbitrary plain text containing vulnerability and ticket metadata.
func ParseTickets(data []byte) ([]*Ticket, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("empty ticket input")
	}

	// 1. If it looks like a JSON array, attempt to parse each element.
	if trimmed[0] == '[' {
		var rawList []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawList); err == nil && len(rawList) > 0 {
			var out []*Ticket
			for _, item := range rawList {
				t, err := parseSingleTicketJSON(item)
				if err == nil && (t.Vulnerability != "" || t.ID != "") {
					out = append(out, t)
				}
			}
			if len(out) > 0 {
				return out, nil
			}
		}
	}

	// 2. If it looks like a JSON object, attempt to parse it.
	if trimmed[0] == '{' {
		t, err := parseSingleTicketJSON(trimmed)
		if err == nil {
			return []*Ticket{t}, nil
		}
	}

	// 3. Fallback: Parse as arbitrary plain text.
	t, err := parseTextTicket(string(trimmed))
	if err != nil {
		return nil, err
	}
	return []*Ticket{t}, nil
}

var (
	reGO   = regexp.MustCompile(`(?i)\b(GO-\d{4}-\d+)\b`)
	reCVE  = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{4,7})\b`)
	reGHSA = regexp.MustCompile(`(?i)\b(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b`)
	reBDU  = regexp.MustCompile(`(?i)\b(BDU:\d{4}-\d+)\b`)

	reTicketKey = regexp.MustCompile(`\b([A-Z]{2,15}-\d+)\b`)
	reGoModule  = regexp.MustCompile(`\b((?:github\.com|golang\.org|google\.golang\.org|gopkg\.in|gitlab\.com)/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)*)\b`)

	reComponentLabel = regexp.MustCompile(`(?i)(?:компонент|component)[\s:=]+([^\r\n,;]+)`)
	reProductLabel   = regexp.MustCompile(`(?i)(?:версия продукта|продукт|product version|product|release|релиз)[\s:=]+([^\r\n,;]+)`)
	rePackageLabel   = regexp.MustCompile(`(?i)(?:библиотека|пакет|модуль|library|package|module)[\s:=]+([^\s,;]+)`)
	reVersionLabel   = regexp.MustCompile(`(?i)(?:версия библиотеки|версия пакета|версия|version|ver)[\s:=]+([^\s,;]+)`)
)

func extractVulnIDs(s string) []string {
	var results []string
	seen := make(map[string]bool)
	add := func(matches []string) {
		for _, m := range matches {
			upper := strings.ToUpper(m)
			if !seen[upper] {
				seen[upper] = true
				results = append(results, upper)
			}
		}
	}
	add(reGO.FindAllString(s, -1))
	add(reCVE.FindAllString(s, -1))
	add(reGHSA.FindAllString(s, -1))
	add(reBDU.FindAllString(s, -1))
	return results
}

func isVulnID(s string) bool {
	upper := strings.ToUpper(strings.TrimSpace(s))
	return reGO.MatchString(upper) || reCVE.MatchString(upper) || reGHSA.MatchString(upper) || reBDU.MatchString(upper)
}

func extractTicketID(s string) string {
	matches := reTicketKey.FindAllString(s, -1)
	for _, m := range matches {
		upper := strings.ToUpper(m)
		if isVulnID(upper) ||
			strings.HasPrefix(upper, "EV-") ||
			strings.HasPrefix(upper, "TX-") ||
			strings.HasPrefix(upper, "C-") ||
			strings.HasPrefix(upper, "H-") {
			continue
		}
		return upper
	}
	return ""
}

func stringValue(v any) string {
	if v == nil {
		return ""
	}
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	case []string:
		for _, s := range val {
			if strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func stringSliceValue(v any) []string {
	if v == nil {
		return nil
	}
	var out []string
	switch val := v.(type) {
	case string:
		if s := strings.TrimSpace(val); s != "" {
			out = append(out, s)
		}
	case []any:
		for _, item := range val {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	case []string:
		for _, s := range val {
			if strings.TrimSpace(s) != "" {
				out = append(out, strings.TrimSpace(s))
			}
		}
	}
	return out
}

func findField(m map[string]any, exactKeys []string, keywordFragments ...string) string {
	for _, target := range exactKeys {
		for k, v := range m {
			if strings.EqualFold(k, target) {
				if s := stringValue(v); s != "" {
					return s
				}
			}
		}
	}
	for _, frag := range keywordFragments {
		for k, v := range m {
			lowerK := strings.ToLower(k)
			if strings.Contains(lowerK, frag) {
				if s := stringValue(v); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func findFieldSlice(m map[string]any, exactKeys []string, keywordFragments ...string) []string {
	var out []string
	seen := make(map[string]bool)
	add := func(v any) {
		for _, s := range stringSliceValue(v) {
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
	}

	for _, target := range exactKeys {
		for k, v := range m {
			if strings.EqualFold(k, target) {
				add(v)
			}
		}
	}
	for _, frag := range keywordFragments {
		for k, v := range m {
			lowerK := strings.ToLower(k)
			if strings.Contains(lowerK, frag) {
				add(v)
			}
		}
	}
	return out
}

func parseSingleTicketJSON(data []byte) (*Ticket, error) {
	// First check standard Ticket schema
	var std Ticket
	if err := json.Unmarshal(data, &std); err == nil && std.Vulnerability != "" {
		if std.Package != "" && std.Module == "" {
			std.Module = std.Package
		}
		if std.Package != "" && len(std.Imports) == 0 {
			std.Imports = []string{std.Package}
		}
		return &std, nil
	}

	// Try custom tracker map
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	t := &Ticket{}
	// Extract standard or custom ticket ID
	if id := findField(m, []string{"id", "code", "key", "ticket", "ticket_id", "issue_key", "issue_id", "task_id"}, "ticket", "issue"); id != "" && !isVulnID(id) {
		t.ID = id
	}

	// Extract vulnerability IDs
	vulnCandidates := findFieldSlice(m,
		[]string{"vulnerability", "vuln", "cve", "ghsa", "go_id", "vulnerabilities", "vuln_id"},
		"vulnerabilit", "vuln", "cve")
	if len(vulnCandidates) == 0 {
		// Fallback: search all string values in m
		vulnCandidates = extractVulnIDs(string(data))
	}
	if len(vulnCandidates) > 0 {
		t.Vulnerability = vulnCandidates[0]
		if len(vulnCandidates) > 1 {
			t.Aliases = vulnCandidates[1:]
		}
	}

	// If ID still empty, scan summary or description for ticket key
	if t.ID == "" {
		summary := findField(m, []string{"summary", "title", "name", "subject", "header"}, "summary", "title")
		if id := extractTicketID(summary); id != "" {
			t.ID = id
		} else {
			desc := findField(m, []string{"description", "details", "body", "text"}, "description")
			if id := extractTicketID(desc); id != "" {
				t.ID = id
			}
		}
	}

	// Component & Product
	t.Component = findField(m, []string{"component", "component_name", "service", "service_name", "app", "project"}, "component")
	t.Product = findField(m, []string{"product", "product_name", "product_code", "project_code"}, "product")
	t.Release = findField(m, []string{"release", "product_version", "target_version", "milestone"}, "release")

	// Package & Module
	t.Package = findField(m, []string{"package", "pkg", "module", "library", "lib"}, "package", "module")
	t.Module = findField(m, []string{"module"}, "module")
	if t.Module == "" && t.Package != "" {
		t.Module = t.Package
	}
	if len(t.Imports) == 0 && t.Package != "" {
		t.Imports = []string{t.Package}
	}

	// Version
	t.Version = findField(m, []string{"version", "fixed_version", "affected_version", "package_version"}, "version")
	t.FixedVersions = findFieldSlice(m, []string{"fixed_versions", "fixed_version"}, "fixed_version")

	// Summary & Description & Rationale
	t.Summary = findField(m, []string{"summary", "title", "name", "subject"}, "summary", "title")
	t.Description = findField(m, []string{"description", "details", "body", "text"}, "description")
	t.Rationale = findField(m, []string{"rationale", "comment", "notes", "analysis", "resolution", "result"}, "rationale", "comment", "analysis", "result")
	t.Repo = findField(m, []string{"repo", "repository"}, "repo")

	type osvWrapper struct {
		OSV json.RawMessage `json:"osv"`
	}
	var ow osvWrapper
	if err := json.Unmarshal(data, &ow); err == nil && len(ow.OSV) > 0 {
		t.OSV = ow.OSV
	}

	if t.Vulnerability == "" {
		return nil, fmt.Errorf("no vulnerability identifier found in ticket (expected GO-*, CVE-*, GHSA-*, BDU:*)")
	}

	return t, nil
}

func parseTextTicket(text string) (*Ticket, error) {
	vulnIDs := extractVulnIDs(text)
	if len(vulnIDs) == 0 {
		return nil, fmt.Errorf("no vulnerability identifier found in ticket text (expected GO-*, CVE-*, GHSA-*, BDU:*)")
	}

	t := &Ticket{
		Vulnerability: vulnIDs[0],
	}
	if len(vulnIDs) > 1 {
		t.Aliases = vulnIDs[1:]
	}

	t.ID = extractTicketID(text)

	// Component
	if m := reComponentLabel.FindStringSubmatch(text); len(m) > 1 {
		t.Component = strings.TrimSpace(m[1])
	}

	// Product / Release
	if m := reProductLabel.FindStringSubmatch(text); len(m) > 1 {
		t.Release = strings.TrimSpace(m[1])
	}

	// Package
	if m := rePackageLabel.FindStringSubmatch(text); len(m) > 1 {
		t.Package = strings.TrimSpace(m[1])
	} else if m := reGoModule.FindStringSubmatch(text); len(m) > 1 {
		t.Package = strings.TrimSpace(m[1])
	}

	if t.Package != "" {
		t.Module = t.Package
		t.Imports = []string{t.Package}
	}

	// Version
	if m := reVersionLabel.FindStringSubmatch(text); len(m) > 1 {
		t.Version = strings.TrimSpace(m[1])
	}

	t.Description = strings.TrimSpace(text)
	return t, nil
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
	case t.Module != "" && len(t.FixedVersions) > 0:
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
