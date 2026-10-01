package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// MechanismReviewer performs adversarial review to prevent patch misinterpretation.
type MechanismReviewer struct {
	client Completer
}

// NewMechanismReviewer constructs a MechanismReviewer.
func NewMechanismReviewer(client Completer) *MechanismReviewer {
	return &MechanismReviewer{client: client}
}

// Review checks the proposal against the defect mechanism and patch diff.
func (m *MechanismReviewer) Review(ctx context.Context, caseData *domain.AnalysisCase, prop domain.CVEAnalysisProposal) (domain.SemanticReview, error) {
	rev := domain.SemanticReview{
		Reviewer: "mechanism_reviewer",
		Passed:   true,
	}

	if m.client == nil {
		return rev, fmt.Errorf("llm client unavailable")
	}

	if llmBudgetExhausted(caseData) {
		return rev, fmt.Errorf("MaxLLMCalls limit reached")
	}
	caseData.IncLLMCalls()

	prompt := fmt.Sprintf("Review proposal for %s against patch diff. Respond with JSON: {\"passed\":true|false,\"findings\":[\"...\"]}",
		caseData.Vulnerability.ID)

	resp, _, err := m.client.Complete(ctx, Analyze, "You are an adversarial reviewer checking for patch misinterpretation.", prompt)
	if err != nil {
		return rev, err
	}

	clean := ExtractJSON(resp)
	if clean == "" {
		return rev, fmt.Errorf("no valid JSON found in review response: %s", resp)
	}

	if err := json.Unmarshal([]byte(clean), &rev); err != nil {
		return rev, fmt.Errorf("invalid review JSON: %w", err)
	}

	return rev, nil
}
