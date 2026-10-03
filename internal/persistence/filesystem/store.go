package filesystem

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
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

// PriorCase loads the most recently started stored case for the same
// vulnerability and repository, excluding excludeID — the baseline a
// rerun's tool-execution hashes are diffed against. Returns nil when no
// prior run exists or stored cases cannot be read.
func (s *Store) PriorCase(ctx context.Context, vulnID, repo string, excludeID domain.CaseID) *domain.AnalysisCase {
	entries, err := filepath.Glob(filepath.Join(s.Root, "*.json"))
	if err != nil {
		return nil
	}
	var best *domain.AnalysisCase
	for _, p := range entries {
		c, err := s.Load(ctx, domain.CaseID(strings.TrimSuffix(filepath.Base(p), ".json")))
		if err != nil || c.ID == excludeID {
			continue
		}
		if c.Vulnerability.ID != vulnID || c.Product.Repository != repo {
			continue
		}
		if best == nil || c.Workflow.StartedAt.After(best.Workflow.StartedAt) {
			best = c
		}
	}
	return best
}
