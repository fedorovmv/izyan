package filesystem

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"example.com/vuln-analyzer/internal/domain"
)

type Store struct {
	Root string
}

func New(root string) *Store { return &Store{Root: root} }

func (s *Store) Create(ctx context.Context, c *domain.AnalysisCase) error {
	return s.Save(ctx, c)
}

func (s *Store) Load(_ context.Context, id domain.CaseID) (*domain.AnalysisCase, error) {
	b, err := os.ReadFile(s.path(id))
	if err != nil {
		return nil, err
	}
	var c domain.AnalysisCase
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

func (s *Store) Save(_ context.Context, c *domain.AnalysisCase) error {
	if err := os.MkdirAll(s.Root, 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path(c.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path(c.ID)); err != nil {
		return fmt.Errorf("atomic save: %w", err)
	}
	return nil
}

func (s *Store) path(id domain.CaseID) string {
	return filepath.Join(s.Root, string(id)+".json")
}
