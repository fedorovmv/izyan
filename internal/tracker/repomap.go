package tracker

import (
	"encoding/json"
	"os"
	"strings"
)

// RepoMap resolves repository paths for tickets by component, product, or ticket key.
// It supports either a flat JSON object {"GATEWAY": "/path/to/repo"} or a structured JSON:
//
//	{
//	  "components": { "GATEWAY": "/path/to/repo" },
//	  "products":   { "APP": "/path/to/repo" },
//	  "tickets":    { "SEC-1234": "/path/to/repo" }
//	}
type RepoMap struct {
	Components map[string]string `json:"components,omitempty"`
	Products   map[string]string `json:"products,omitempty"`
	Tickets    map[string]string `json:"tickets,omitempty"`
	Direct     map[string]string `json:"-"`
}

// LoadRepoMap reads and parses a repo map JSON file.
func LoadRepoMap(path string) (*RepoMap, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	rm := &RepoMap{
		Components: make(map[string]string),
		Products:   make(map[string]string),
		Tickets:    make(map[string]string),
		Direct:     make(map[string]string),
	}

	// Try structured format first.
	if err := json.Unmarshal(b, rm); err == nil && (len(rm.Components) > 0 || len(rm.Products) > 0 || len(rm.Tickets) > 0) {
		return rm, nil
	}

	// Try flat map format.
	var flat map[string]string
	if err := json.Unmarshal(b, &flat); err == nil {
		rm.Direct = flat
		return rm, nil
	}

	return nil, err
}

// Resolve looks up a repository path for the given ticket.
// Precedence: component -> product -> ticket ID.
func (m *RepoMap) Resolve(t *Ticket) string {
	if m == nil || t == nil {
		return ""
	}

	lookup := func(key string) string {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			return ""
		}

		// Exact or case-insensitive match against all tables.
		for _, tbl := range []map[string]string{m.Direct, m.Components, m.Products, m.Tickets} {
			for k, v := range tbl {
				if strings.EqualFold(k, trimmed) {
					return v
				}
			}
		}

		// If key contains multiple words (e.g. "GATEWAY 1.2.0-release"), try first token ("GATEWAY").
		fields := strings.Fields(trimmed)
		if len(fields) > 1 {
			first := fields[0]
			for _, tbl := range []map[string]string{m.Direct, m.Components, m.Products, m.Tickets} {
				for k, v := range tbl {
					if strings.EqualFold(k, first) {
						return v
					}
				}
			}
		}

		return ""
	}

	if repo := lookup(t.Component); repo != "" {
		return repo
	}
	if repo := lookup(t.Product); repo != "" {
		return repo
	}
	if repo := lookup(t.ID); repo != "" {
		return repo
	}

	return ""
}
