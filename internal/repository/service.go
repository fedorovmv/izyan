package repository

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	gomod := goModDirective(path)
	goos := opts.GOOS
	if goos == "" {
		goos = runtime.GOOS
	}
	goarch := opts.GOARCH
	if goarch == "" {
		goarch = runtime.GOARCH
	}
	return domain.ProductSnapshot{
		Repository:     path,
		Commit:         commit,
		GoVersion:      goversion,
		GoModDirective: gomod,
		GOOS:           goos,
		GOARCH:         goarch,
		BuildTags:      opts.BuildTags,
	}, nil
}

// goModDirective returns the `go` directive of the module's go.mod — the
// minimum toolchain the module declares. The release binary may have been
// built with a newer toolchain, which matters for stdlib advisories.
func goModDirective(path string) string {
	b, err := os.ReadFile(filepath.Join(path, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "go ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "go "))
		}
	}
	return ""
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
