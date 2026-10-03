package workflow

import (
	"context"
	"fmt"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/persistence"
)

type Transition struct {
	Next   domain.WorkflowState
	Reason string
}

type StateHandler interface {
	State() domain.WorkflowState
	Run(ctx context.Context, c *domain.AnalysisCase) (Transition, error)
}

type Engine struct {
	handlers map[domain.WorkflowState]StateHandler
	store    persistence.CaseStore
}

func New(store persistence.CaseStore, handlers ...StateHandler) *Engine {
	m := make(map[domain.WorkflowState]StateHandler, len(handlers))
	for _, h := range handlers {
		m[h.State()] = h
	}
	return &Engine{handlers: m, store: store}
}

func (e *Engine) Run(ctx context.Context, c *domain.AnalysisCase) error {
	for !isTerminal(c.Workflow.State) {
		h, ok := e.handlers[c.Workflow.State]
		if !ok {
			return fmt.Errorf("no handler for state %s", c.Workflow.State)
		}
		start := time.Now()
		tr, err := h.Run(ctx, c)
		if err != nil {
			return err
		}
		if c.Workflow.Timings == nil {
			c.Workflow.Timings = map[string]float64{}
		}
		c.Workflow.Timings[string(c.Workflow.State)] += time.Since(start).Seconds()
		c.Workflow.PreviousState = c.Workflow.State
		c.Workflow.State = tr.Next
		c.Workflow.Reason = tr.Reason
		c.Workflow.UpdatedAt = time.Now().UTC()
		c.Workflow.Iteration++
		if lim := c.Workflow.Limits.MaxIterations; lim > 0 && c.Workflow.Iteration >= lim && !isTerminal(tr.Next) {
			c.Workflow.State = domain.StateInconclusive
			c.Workflow.Reason = "analysis budget exhausted (max iterations)"
		}
		if err := e.store.Save(ctx, c); err != nil {
			return err
		}
	}
	return nil
}

func isTerminal(s domain.WorkflowState) bool {
	return s == domain.StateCompleted || s == domain.StateInconclusive || s == domain.StateFailed
}
