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

	propJSON, _ := json.Marshal(prop)
	patchSnippet := ""
	if caseData.CVEAnalysisBundle != nil {
		patchSnippet = caseData.CVEAnalysisBundle.PatchDiff
		if len(patchSnippet) > 2000 {
			patchSnippet = patchSnippet[:2000]
		}
	}
	prompt := fmt.Sprintf("Advisory: %s\nProposal: %s\nPatch snippet: %s\nReview whether the proposal misinterprets the patch. Respond with strict JSON: {\"passed\":true,\"findings\":[]}",
		caseData.Vulnerability.Summary, string(propJSON), patchSnippet)

	resp, finish, err := m.client.Complete(ctx, Analyze, "You are a code review assistant evaluating a defect analysis proposal. Do not invoke tools. Output JSON only.", prompt)
	if err != nil {
		return rev, err
	}
	if IsRefusal(resp, finish) {
		return rev, fmt.Errorf("llm refusal in mechanism review: %s", DescribeBadOutput(resp, finish))
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
