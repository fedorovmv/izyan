package llm_test

import (
	"context"
	"encoding/json"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/llm"
)

type mockLLMClient struct {
	responses []string
	callIndex int
}

func (m *mockLLMClient) Complete(ctx context.Context, role llm.ModelRole, system, user string) (string, string, error) {
	if m.callIndex < len(m.responses) {
		resp := m.responses[m.callIndex]
		m.callIndex++
		return resp, "", nil
	}
	return "{}", "", nil
}

type mockRunner struct{}

func (m *mockRunner) Call(ctx context.Context, caseData *domain.AnalysisCase, toolName string, args json.RawMessage) llm.ToolResult {
	raw, _ := json.Marshal("diff content")
	return llm.ToolResult{OK: true, Content: raw}
}

func TestResearcher_RespectsMaxIterations(t *testing.T) {
	client := &mockLLMClient{
		responses: []string{
			`{"action":"tool","tool":"read_patch_diff","args":{}}`,
			`{"action":"final","proposal":{"id":"P-1","mechanisms":[{"id":"M-1","summary":"panic in RouteAndProcess","faulting_sites":["pkg.RouteAndProcess"]}],"confidence":"HIGH"}}`,
		},
	}

	researcher := llm.NewResearcher(client, &mockRunner{}, 8)
	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{ID: "GO-2026-6443"},
	}

	proposal, err := researcher.Research(context.Background(), caseData)
	if err != nil {
		t.Fatalf("research failed: %v", err)
	}

	if proposal.ID != "P-1" {
		t.Errorf("got %q, want P-1", proposal.ID)
	}
	if len(proposal.Mechanisms) != 1 {
		t.Fatalf("got %d mechanisms, want 1", len(proposal.Mechanisms))
	}
	if proposal.ToolIterations != 2 {
		t.Errorf("got %d tool iterations, want 2", proposal.ToolIterations)
	}
}

func TestResearcher_BudgetExhaustion(t *testing.T) {
	client := &mockLLMClient{
		responses: []string{
			`{"action":"tool","tool":"read_patch_diff","args":{}}`,
		},
	}

	researcher := llm.NewResearcher(client, &mockRunner{}, 8)
	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{ID: "GO-2026-6443"},
		Workflow: domain.WorkflowStatus{
			Limits: domain.AnalysisLimits{
				MaxLLMCalls: 1,
			},
		},
	}

	// First call consumes the 1 allowed LLM call
	caseData.IncLLMCalls()

	_, err := researcher.Research(context.Background(), caseData)
	if err == nil {
		t.Fatalf("expected error due to MaxLLMCalls exhausted, got nil")
	}
}
