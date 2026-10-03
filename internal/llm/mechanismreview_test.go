package llm_test

import (
	"context"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/llm"
)

func TestMechanismReviewer_DetectsMisinterpretation(t *testing.T) {
	client := &mockLLMClient{
		responses: []string{
			`{"passed":false,"findings":["proposal claims defect is in crypto, but patch touches transport"]}`,
		},
	}

	reviewer := llm.NewMechanismReviewer(client)
	caseData := &domain.AnalysisCase{}
	prop := domain.CVEAnalysisProposal{
		Mechanisms: []domain.DefectMechanism{
			{Summary: "wrong description"},
		},
	}

	rev, err := reviewer.Review(context.Background(), caseData, prop)
	if err != nil {
		t.Fatalf("Review failed: %v", err)
	}
	if rev.Passed {
		t.Errorf("expected review to fail on misinterpretation")
	}
	if len(rev.Findings) != 1 {
		t.Errorf("got %d findings, want 1", len(rev.Findings))
	}
}

func TestMechanismReviewer_BudgetExhaustion(t *testing.T) {
	client := &mockLLMClient{}
	reviewer := llm.NewMechanismReviewer(client)
	caseData := &domain.AnalysisCase{
		Workflow: domain.WorkflowStatus{
			Limits: domain.AnalysisLimits{
				MaxLLMCalls: 1,
			},
		},
	}
	caseData.IncLLMCalls()

	_, err := reviewer.Review(context.Background(), caseData, domain.CVEAnalysisProposal{})
	if err == nil {
		t.Fatalf("expected budget error, got nil")
	}
}
