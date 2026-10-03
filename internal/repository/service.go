package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/toolaudit"
)

type SnapshotOptions struct {
	GOOS      string
	GOARCH    string
	BuildTags []string
	// BinaryPath points at the release-built artifact. When set, the embedded
	// build info (`go version -m`) supplies the real toolchain and module
	// versions — the ground truth a ticket refers to, unlike go.mod which is
	// only a minimum.
	BinaryPath string
	// ReleaseGoVersion is the toolchain version that built the release, when
	// known from the ticket/pipeline metadata.
	ReleaseGoVersion string
	// TrustedPeer indicates the service communicates strictly with trusted peers
	// in trusted infrastructure.
	TrustedPeer bool
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
	releaseGo := opts.ReleaseGoVersion
	if opts.BinaryPath != "" {
		if v, berr := binaryGoVersion(ctx, opts.BinaryPath); berr == nil && v != "" {
			releaseGo = v // embedded build info wins over ticket metadata
		}
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
		Repository:       path,
		Commit:           commit,
		GoVersion:        goversion,
		GoModDirective:   gomod,
		ReleaseGoVersion: releaseGo,
		BinaryPath:       opts.BinaryPath,
		GOOS:             goos,
		GOARCH:           goarch,
		BuildTags:        opts.BuildTags,
		TrustedPeer:      opts.TrustedPeer,
	}, nil
}

// BinaryGoVersion reports the toolchain version embedded in a Go binary —
// used to select the analysis toolchain when --binary is provided without
// an explicit --release-go-version.
func BinaryGoVersion(ctx context.Context, bin string) (string, error) {
	return binaryGoVersion(ctx, bin)
}

// BinaryBuildInfo returns the full `go version -m` output for a release
// binary: embedded toolchain, module versions and build settings — the
// artifact's own runtime facts, authoritative over go.mod claims.
func BinaryBuildInfo(ctx context.Context, bin string) (string, error) {
	return command(ctx, filepath.Dir(bin), "go", "version", "-m", bin)
}

// binaryGoVersion extracts the toolchain embedded in a Go binary via
// `go version -m`: the first line ends with the toolchain version.
func binaryGoVersion(ctx context.Context, bin string) (string, error) {
	out, err := BinaryBuildInfo(ctx, bin)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, ": go"); i >= 0 {
			return strings.TrimSpace(line[i+2:]), nil
		}
	}
	return "", fmt.Errorf("no toolchain in go version -m output")
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
	b, _, err := toolaudit.Run(ctx, filepath.Base(name), "", dir, name, nil, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
