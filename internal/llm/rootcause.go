package llm

import (
	"context"
	"encoding/json"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// RootCauseResolver proposes root-cause candidates with the build model
// when the deterministic resolver cannot resolve the advisory (no
// affected symbols, no usable fix diff). Candidates are NOT evidence —
// the caller's Verifier still checks each symbol in the product's
// dependency source. Unverifiable proposals become alternatives.
type RootCauseResolver struct {
	Client   *Client
	proposed bool
	Fallback interface {
		Resolve(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error)
	}
}

const rootCauseSystem = `You are a root cause analyst for Go vulnerabilities.
Given an OSV-style advisory, identify the Go functions/methods whose code
contains the vulnerability (the sinks an attacker would reach). Output a
JSON array only:
[{"package":"<import path>","symbol":"<Func or Type.Method WITHOUT package prefix>","mechanism":"<one sentence>"}]
Rules: only public API surface functions likely reachable from a consumer;
prefer the advisory's own hints (function names, file names, references);
if you cannot name at least one plausible symbol, output [].`

// proposed memoizes the one-shot proposal call so a later retry
// (Proposer hook after failed verification) does not burn a second
// LLM call for the same advisory.
func (r *RootCauseResolver) Resolve(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error) {
	model, evs, err := r.Fallback.Resolve(ctx, c, v)
	if err != nil || (model != nil && model.Status == domain.RootCauseResolved) {
		return model, evs, err
	}
	props, lims, err := r.Propose(ctx, c, v)
	model.Limitations = append(model.Limitations, lims...)
	if err != nil || len(props) == 0 {
		return model, evs, err
	}
	model.RootCauses = props
	model.Status = domain.RootCauseResolved
	model.Limitations = append(model.Limitations,
		"root cause candidates proposed by LLM; each was verified against dependency source")
	return model, evs, nil
}

// Propose asks the build model for sink candidates. Implements the
// states.RootCauseProposer hook so the workflow can request fresh
// candidates when deterministic ones fail source verification.
func (r *RootCauseResolver) Propose(ctx context.Context, c *domain.AnalysisCase, v domain.Vulnerability) ([]domain.RootCause, []string, error) {
	var lims []string
	if r.Client == nil || llmBudgetExhausted(c) || r.proposed {
		return nil, nil, nil
	}
	r.proposed = true

	user, _ := json.Marshal(struct {
		ID          string   `json:"id"`
		Summary     string   `json:"summary"`
		Description string   `json:"description"`
		Packages    []string `json:"affected_packages"`
		Symbols     []string `json:"affected_symbols"`
		References  []string `json:"references"`
	}{v.ID, v.Summary, v.Description, affectedPackages(v), affectedSymbols(v), referenceURLs(v)})
	var props []struct {
		Package   string `json:"package"`
		Symbol    string `json:"symbol"`
		Mechanism string `json:"mechanism"`
	}
	parseOK := false
	for attempt := 0; attempt <= r.Client.Retries(); attempt++ {
		c.IncLLMCalls()
		out, callErr := r.Client.Complete(ctx, Build, rootCauseSystem, string(user))
		if callErr != nil {
			lims = append(lims, "llm root cause proposal failed: "+callErr.Error())
			break
		}
		if j := ExtractJSON(out); j != "" && json.Unmarshal([]byte(j), &props) == nil && len(props) > 0 {
			parseOK = true
			break
		}
	}
	if !parseOK {
		return nil, append(lims, "llm root cause proposal unusable"), nil
	}
	var out []domain.RootCause
	for i, p := range props {
		if i >= 10 || p.Package == "" || p.Symbol == "" {
			continue
		}
		out = append(out, domain.RootCause{
			Package:   p.Package,
			Symbol:    normalizeSymbol(p.Package, p.Symbol),
			Role:      domain.RootCauseSink,
			Mechanism: "llm-proposed: " + p.Mechanism,
		})
	}
	return out, lims, nil
}

// normalizeSymbol strips a package-name prefix the model commonly adds:
// package golang.org/x/net/html + symbol "html.Parse" -> "Parse".
func normalizeSymbol(pkg, sym string) string {
	base := pkg
	if i := strings.LastIndex(pkg, "/"); i >= 0 {
		base = pkg[i+1:]
	}
	return strings.TrimPrefix(sym, base+".")
}

func affectedPackages(v domain.Vulnerability) []string {
	var out []string
	for _, p := range v.AffectedPackages {
		out = append(out, p.Path)
	}
	return out
}

func referenceURLs(v domain.Vulnerability) []string {
	var out []string
	for _, r := range v.References {
		out = append(out, r.URL)
	}
	return out
}

func affectedSymbols(v domain.Vulnerability) []string {
	var out []string
	for _, s := range v.AffectedSymbols {
		out = append(out, s.Package+"."+s.Symbol)
	}
	return out
}
