package repository

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

type SnapshotOptions struct {
	GOOS      string
	GOARCH    string
	BuildTags []string
}

type Snapshotter interface {
	Snapshot(ctx context.Context, path string, opts SnapshotOptions) (domain.ProductSnapshot, error)
}

type Service struct{}

func (Service) Snapshot(ctx context.Context, path string, opts SnapshotOptions) (domain.ProductSnapshot, error) {
	commit, err := command(ctx, path, "git", "rev-parse", "HEAD")
	if err != nil {
		return domain.ProductSnapshot{}, fmt.Errorf("resolve git commit: %w", err)
	}
	goversion, err := command(ctx, path, "go", "version")
	if err != nil {
		return domain.ProductSnapshot{}, fmt.Errorf("go version: %w", err)
	}
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := opts.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return domain.ProductSnapshot{
		Repository: path,
		Commit:     commit,
		GoVersion:  goversion,
		GOOS:       goos,
		GOARCH:     goarch,
		BuildTags:  opts.BuildTags,
	}, nil
}

func command(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	b, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
