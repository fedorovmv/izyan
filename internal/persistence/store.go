package persistence

import (
	"context"

	"github.com/fedorovmv/izyan/internal/domain"
)

type CaseStore interface {
	Create(ctx context.Context, c *domain.AnalysisCase) error
	Load(ctx context.Context, id domain.CaseID) (*domain.AnalysisCase, error)
	Save(ctx context.Context, c *domain.AnalysisCase) error
}
