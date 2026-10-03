package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

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

// ResolveRef resolves a version, release string, branch name, or tag to a canonical ref name
// and commit SHA in the given git repository.
func ResolveRef(ctx context.Context, repoPath, releaseOrRef string) (string, string, error) {
	releaseOrRef = strings.TrimSpace(releaseOrRef)
	if releaseOrRef == "" {
		return "", "", fmt.Errorf("empty release or ref specified")
	}

	// Try prioritized candidates first
	for _, cand := range refCandidates(releaseOrRef) {
		sha, err := command(ctx, repoPath, "git", "rev-parse", "--verify", "--quiet", cand+"^{commit}")
		if err == nil && sha != "" {
			return cand, sha, nil
		}
	}

	// Fallback: search git tag list for fuzzy matches
	tagsOut, err := command(ctx, repoPath, "git", "tag", "-l")
	if err == nil && tagsOut != "" {
		tags := strings.Split(tagsOut, "\n")
		normalizedTarget := normalizeRef(releaseOrRef)
		for _, tag := range tags {
			tag = strings.TrimSpace(tag)
			if tag == "" {
				continue
			}
			if normalizeRef(tag) == normalizedTarget {
				sha, err := command(ctx, repoPath, "git", "rev-parse", "--verify", "--quiet", tag+"^{commit}")
				if err == nil && sha != "" {
					return tag, sha, nil
				}
			}
		}
	}

	return "", "", fmt.Errorf("release or git ref %q not found in repository", releaseOrRef)
}

func refCandidates(ref string) []string {
	s := strings.TrimSpace(ref)
	if s == "" {
		return nil
	}
	var list []string
	seen := make(map[string]bool)
	add := func(c string) {
		c = strings.TrimSpace(c)
		if c != "" && !seen[c] {
			seen[c] = true
			list = append(list, c)
		}
	}

	// 1. Direct ref as passed
	add(s)

	// 2. Trim / add 'v' prefix
	noV := strings.TrimPrefix(s, "v")
	add("v" + noV)
	add(noV)

	// 3. Common release branch/tag prefixes
	add("release/" + s)
	add("release/" + noV)
	add("release/v" + noV)
	add("rel-" + s)
	add("rel-" + noV)
	add("tags/" + s)
	add("tags/v" + noV)

	// 4. If 2 segments (e.g. 24.2 or 2.0), try appending .0
	parts := strings.Split(noV, ".")
	if len(parts) == 2 {
		dotZero := noV + ".0"
		add(dotZero)
		add("v" + dotZero)
		add("release/" + dotZero)
		add("release/v" + dotZero)
		add("rel-" + dotZero)
	}

	return list
}

func normalizeRef(r string) string {
	r = strings.ToLower(strings.TrimSpace(r))
	r = strings.TrimPrefix(r, "refs/tags/")
	r = strings.TrimPrefix(r, "release/")
	r = strings.TrimPrefix(r, "rel-")
	r = strings.TrimPrefix(r, "tags/")
	r = strings.TrimPrefix(r, "v")
	return r
}

// NewWorktree creates an isolated git worktree at a temporary directory checked out
// to commitOrRef. The returned cleanup function removes the worktree and its temporary directory.
func NewWorktree(ctx context.Context, repoPath, commitOrRef string) (string, func(), error) {
	commitOrRef = strings.TrimSpace(commitOrRef)
	if commitOrRef == "" {
		return "", nil, fmt.Errorf("empty commit or ref for worktree")
	}

	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return "", nil, fmt.Errorf("resolve repo path: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "izyan-worktree-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp worktree dir: %w", err)
	}

	_, err = command(ctx, absRepo, "git", "worktree", "add", "--detach", tmpDir, commitOrRef)
	if err != nil {
		_ = os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("git worktree add: %w", err)
	}

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_, _ = command(cleanCtx, absRepo, "git", "worktree", "remove", "--force", tmpDir)
			_ = os.RemoveAll(tmpDir)
		})
	}

	return tmpDir, cleanup, nil
}
