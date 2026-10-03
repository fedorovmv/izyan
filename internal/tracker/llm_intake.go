package tracker

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// TextCompleter runs a system+user chat completion.
type TextCompleter interface {
	Complete(ctx context.Context, system, user string) (string, error)
}

const ticketExtractorSystemPrompt = `You are a security vulnerability metadata extractor for Go applications.
Your job is to read arbitrary user text (which may be a ticket, chat message, email, or issue description in Russian or English) and extract structured information about the vulnerability.

Output ONLY a single valid JSON object with the following fields:
{
  "vulnerability": "<primary GO-*, CVE-*, GHSA-*, or BDU:* identifier>",
  "aliases": ["<other vulnerability identifiers if mentioned>"],
  "ticket_id": "<external issue tracker key, e.g. PROJ-1234, if mentioned>",
  "package": "<Go module or package path, e.g. github.com/user/repo, or package name>",
  "version": "<vulnerable or used version, e.g. v1.2.3, if mentioned>",
  "component": "<component or service name, if mentioned>",
  "product": "<product name or code, if mentioned>",
  "release": "<product release version, if mentioned>",
  "summary": "<one sentence summary of the issue in the language of the input>"
}

Rules:
1. Do not invent or hallucinate vulnerability IDs or package names. Only extract what is stated or directly referenced in the text.
2. If a field is not present or cannot be determined, omit it or set it to empty string "".
3. Return ONLY raw JSON, with no markdown fences, no formatting, and no commentary.`

type llmTicketExtraction struct {
	Vulnerability string   `json:"vulnerability"`
	Aliases       []string `json:"aliases"`
	TicketID      string   `json:"ticket_id"`
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	Component     string   `json:"component"`
	Product       string   `json:"product"`
	Release       string   `json:"release"`
	Summary       string   `json:"summary"`
}

// ExtractTicketWithLLM uses an LLM to extract ticket metadata from arbitrary, unstructured text,
// validating the extracted fields deterministically to avoid hallucinations.
func ExtractTicketWithLLM(ctx context.Context, completer TextCompleter, rawText string) (*Ticket, error) {
	trimmed := strings.TrimSpace(rawText)
	if trimmed == "" {
		return nil, fmt.Errorf("empty ticket text")
	}
	if completer == nil {
		return nil, fmt.Errorf("llm completer is nil")
	}

	resp, err := completer.Complete(ctx, ticketExtractorSystemPrompt, trimmed)
	if err != nil {
		return nil, fmt.Errorf("llm completion: %w", err)
	}

	cleanJSON := extractJSONFromText(resp)
	if cleanJSON == "" {
		return nil, fmt.Errorf("llm returned non-json response")
	}

	var ext llmTicketExtraction
	if err := json.Unmarshal([]byte(cleanJSON), &ext); err != nil {
		return nil, fmt.Errorf("decode llm extraction: %w", err)
	}

	// Deterministic validation gate:
	ext.Vulnerability = strings.ToUpper(strings.TrimSpace(ext.Vulnerability))
	if ext.Vulnerability == "" || !isVulnID(ext.Vulnerability) {
		ids := extractVulnIDs(rawText)
		if len(ids) > 0 {
			ext.Vulnerability = ids[0]
			if len(ids) > 1 {
				ext.Aliases = ids[1:]
			}
		} else {
			return nil, fmt.Errorf("no valid vulnerability identifier extracted by LLM")
		}
	}

	// Anti-hallucination check: ensure the vulnerability ID exists in rawText
	if !containsIgnoringPunctuation(rawText, ext.Vulnerability) {
		realIDs := extractVulnIDs(rawText)
		if len(realIDs) > 0 {
			ext.Vulnerability = realIDs[0]
		} else {
			return nil, fmt.Errorf("extracted vulnerability %s does not appear in source text", ext.Vulnerability)
		}
	}

	t := &Ticket{
		ID:            strings.TrimSpace(ext.TicketID),
		Vulnerability: ext.Vulnerability,
		Package:       strings.TrimSpace(ext.Package),
		Version:       strings.TrimSpace(ext.Version),
		Component:     strings.TrimSpace(ext.Component),
		Product:       strings.TrimSpace(ext.Product),
		Release:       strings.TrimSpace(ext.Release),
		Summary:       strings.TrimSpace(ext.Summary),
		Description:   trimmed,
	}

	// Validate aliases
	for _, a := range ext.Aliases {
		a = strings.ToUpper(strings.TrimSpace(a))
		if a != "" && a != t.Vulnerability && isVulnID(a) && containsIgnoringPunctuation(rawText, a) {
			t.Aliases = append(t.Aliases, a)
		}
	}

	if t.Package != "" {
		t.Module = t.Package
		t.Imports = []string{t.Package}
	}

	return t, nil
}

// extractJSONFromText extracts the first valid JSON block from a response string.
func extractJSONFromText(s string) string {
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i:]
		if j := strings.Index(rest, "\n"); j >= 0 {
			rest = rest[j+1:]
			if k := strings.Index(rest, "```"); k >= 0 {
				s = strings.TrimSpace(rest[:k])
			}
		}
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return ""
}

func containsIgnoringPunctuation(text, substr string) bool {
	clean := func(s string) string {
		var b strings.Builder
		for _, r := range strings.ToLower(s) {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
				b.WriteRune(r)
			}
		}
		return b.String()
	}
	return strings.Contains(clean(text), clean(substr))
}
