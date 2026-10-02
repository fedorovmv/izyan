package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// StrategyPlanner formulates verification plans and obligations.
type StrategyPlanner struct {
	client Completer
}

// NewStrategyPlanner constructs a StrategyPlanner.
func NewStrategyPlanner(client Completer) *StrategyPlanner {
	return &StrategyPlanner{client: client}
}

// Plan formulates a verification strategy plan for the case.
func (p *StrategyPlanner) Plan(ctx context.Context, caseData *domain.AnalysisCase) (domain.StrategyPlan, error) {
	plan := domain.StrategyPlan{
		ID: fmt.Sprintf("PLAN-%s", caseData.Vulnerability.ID),
	}

	if p.client == nil {
		return plan, fmt.Errorf("llm client unavailable")
	}

	if llmBudgetExhausted(caseData) {
		return plan, fmt.Errorf("MaxLLMCalls limit reached")
	}
	caseData.IncLLMCalls()

	prompt := fmt.Sprintf("Advisory: %s\nVulnerability: %s\nFormulate a verification strategy plan. Respond with strict JSON: {\"selected_strategy\":\"...\",\"obligations\":[\"...\"]}",
		caseData.Vulnerability.Summary, caseData.Vulnerability.ID)

	resp, finish, err := p.client.Complete(ctx, Analyze, "You are a verification planner for Go static analysis. Do not invoke tools. Output JSON only.", prompt)
	if err != nil {
		return plan, err
	}
	if IsRefusal(resp, finish) {
		return plan, fmt.Errorf("llm refusal in strategy planning: %s", DescribeBadOutput(resp, finish))
	}

	clean := ExtractJSON(resp)
	if clean == "" {
		return plan, fmt.Errorf("no valid JSON found in strategy response: %s", resp)
	}

	if err := json.Unmarshal([]byte(clean), &plan); err != nil {
		return plan, fmt.Errorf("invalid strategy JSON: %w", err)
	}

	return plan, nil
}
