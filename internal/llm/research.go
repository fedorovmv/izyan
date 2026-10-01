package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// Completer abstracts LLM chat completion.
type Completer interface {
	Complete(ctx context.Context, role ModelRole, system, user string) (string, string, error)
}

// ResearchToolRunner abstracts tool execution for the researcher.
type ResearchToolRunner interface {
	Call(ctx context.Context, caseData *domain.AnalysisCase, toolName string, args json.RawMessage) ToolResult
}

// Researcher conducts bounded CVE analysis using tools and an LLM client.
type Researcher struct {
	client  Completer
	tools   ResearchToolRunner
	maxIter int
}

// NewResearcher constructs a Researcher with a bounded iteration limit (max 8).
func NewResearcher(client Completer, tools ResearchToolRunner, maxIter int) *Researcher {
	if maxIter <= 0 || maxIter > 8 {
		maxIter = 8
	}
	return &Researcher{client: client, tools: tools, maxIter: maxIter}
}

type researcherStep struct {
	Action   string                      `json:"action"` // "tool" or "final"
	Tool     string                      `json:"tool,omitempty"`
	Args     json.RawMessage             `json:"args,omitempty"`
	Proposal *domain.CVEAnalysisProposal `json:"proposal,omitempty"`
}

// Research drives the bounded research loop to isolate faulting sites and auxiliary sites.
func (r *Researcher) Research(ctx context.Context, caseData *domain.AnalysisCase) (domain.CVEAnalysisProposal, error) {
	proposal := domain.CVEAnalysisProposal{
		ID:         fmt.Sprintf("PROP-%s", caseData.Vulnerability.ID),
		Confidence: "LOW",
	}

	if r.client == nil {
		return proposal, fmt.Errorf("llm client unavailable")
	}

	systemPrompt := `You are a Senior Security Research Agent investigating a Go CVE.
Isolate the true faulting defect site from auxiliary dispatchers/guards.
Respond with strict JSON:
{"action":"tool","tool":"<name>","args":{...}} OR
{"action":"final","proposal":{"id":"...","mechanisms":[{"id":"M-1","summary":"...","faulting_sites":["..."],"auxiliary_sites":["..."],"patch_explanation":"..."}],"confidence":"HIGH"}}`

	userContent := fmt.Sprintf("Vulnerability %s: %s\nAffected symbols: %v",
		caseData.Vulnerability.ID, caseData.Vulnerability.Summary, caseData.Vulnerability.AffectedSymbols)

	for iter := 1; iter <= r.maxIter; iter++ {
		if llmBudgetExhausted(caseData) {
			return proposal, fmt.Errorf("MaxLLMCalls limit reached")
		}
		caseData.IncLLMCalls()

		resp, _, err := r.client.Complete(ctx, Analyze, systemPrompt, userContent)
		if err != nil {
			return proposal, err
		}

		j := ExtractJSON(resp)
		var step researcherStep
		if j == "" || json.Unmarshal([]byte(j), &step) != nil {
			userContent += fmt.Sprintf("\nInvalid JSON response. Output valid JSON adhering to schema.")
			continue
		}

		if step.Action == "final" && step.Proposal != nil {
			proposal = *step.Proposal
			proposal.ToolIterations = iter
			return proposal, nil
		}

		if step.Action == "tool" && step.Tool != "" {
			if r.tools == nil {
				return proposal, fmt.Errorf("tools runner unavailable")
			}
			caseData.IncToolCalls()
			res := r.tools.Call(ctx, caseData, step.Tool, step.Args)
			userContent += fmt.Sprintf("\nTool %s result: %s (error: %s)", step.Tool, string(res.Content), res.Error)
			continue
		}

		break
	}

	return proposal, fmt.Errorf("research loop completed without final proposal")
}
