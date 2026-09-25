// Package tracker isolates publishing the human-readable verdict to an
// issue tracker. FileSink writes the markdown comment to disk; a real
// tracker adapter (e.g. SberTrack) can implement Sink later without
// touching the workflow.
package tracker

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Sink receives a tracker-ready markdown comment.
type Sink interface {
	Publish(ctx context.Context, caseID, markdown string) error
}

// FileSink writes the comment to a file next to the report artifacts.
type FileSink struct {
	Dir string
}

func (s FileSink) Publish(_ context.Context, caseID, markdown string) error {
	dir := s.Dir
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(dir, "tracker_comment.md")
	if err := os.WriteFile(path, []byte(markdown), 0o644); err != nil {
		return fmt.Errorf("write tracker comment: %w", err)
	}
	return nil
}
