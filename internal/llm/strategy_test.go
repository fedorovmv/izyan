package llm_test

import (
	"context"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/llm"
)

func TestStrategyPlanner_Plan(t *testing.T) {
	client := &mockLLMClient{
		responses: []string{
			`{"selected_strategy":"locus_and_mode_check","obligations":["verify_package_absence","verify_entrypoint_constructors"]}`,
		},
	}

	planner := llm.NewStrategyPlanner(client)
	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{ID: "GO-2026-6443"},
	}

	plan, err := planner.Plan(context.Background(), caseData)
	if err != nil {
		t.Fatalf("Plan failed: %v", err)
	}
	if plan.SelectedStrategy != "locus_and_mode_check" {
		t.Errorf("got %q, want 'locus_and_mode_check'", plan.SelectedStrategy)
	}
	if len(plan.Obligations) != 2 {
		t.Errorf("got %d obligations, want 2", len(plan.Obligations))
	}
}

func TestStrategyPlanner_BudgetExhaustion(t *testing.T) {
	client := &mockLLMClient{}
	planner := llm.NewStrategyPlanner(client)
	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{ID: "GO-2026-6443"},
		Workflow: domain.WorkflowStatus{
			Limits: domain.AnalysisLimits{
				MaxLLMCalls: 1,
			},
		},
	}
	caseData.IncLLMCalls()

	_, err := planner.Plan(context.Background(), caseData)
	if err == nil {
		t.Fatalf("expected budget error, got nil")
	}
}
