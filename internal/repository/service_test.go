package repository

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func setupTestGitRepo(t *testing.T) (string, map[string]string) {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
		)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %s failed: %v, out: %s", strings.Join(args, " "), err, string(out))
		}
	}

	run("init")
	run("config", "user.name", "Test")
	run("config", "user.email", "test@example.com")

	commits := make(map[string]string)

	// Commit 1 -> tag v1.2.3
	f1 := filepath.Join(dir, "version.txt")
	if err := os.WriteFile(f1, []byte("v1.2.3"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "version.txt")
	run("commit", "-m", "release 1.2.3")
	run("tag", "v1.2.3")
	out, _ := exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	commits["v1.2.3"] = strings.TrimSpace(string(out))

	// Commit 2 -> tag release/2.0
	if err := os.WriteFile(f1, []byte("v2.0"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "version.txt")
	run("commit", "-m", "release 2.0")
	run("tag", "release/2.0")
	out, _ = exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	commits["release/2.0"] = strings.TrimSpace(string(out))

	// Commit 3 -> tag 2026.1
	if err := os.WriteFile(f1, []byte("2026.1"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "version.txt")
	run("commit", "-m", "release 2026.1")
	run("tag", "2026.1")
	out, _ = exec.Command("git", "-C", dir, "rev-parse", "HEAD").Output()
	commits["2026.1"] = strings.TrimSpace(string(out))

	return dir, commits
}

func TestResolveRef(t *testing.T) {
	repoDir, commits := setupTestGitRepo(t)
	ctx := context.Background()

	cases := []struct {
		input       string
		wantRef     string
		wantSHA     string
		expectError bool
	}{
		{input: "v1.2.3", wantRef: "v1.2.3", wantSHA: commits["v1.2.3"]},
		{input: "1.2.3", wantRef: "v1.2.3", wantSHA: commits["v1.2.3"]},
		{input: "release/2.0", wantRef: "release/2.0", wantSHA: commits["release/2.0"]},
		{input: "2.0", wantRef: "release/2.0", wantSHA: commits["release/2.0"]},
		{input: "2026.1", wantRef: "2026.1", wantSHA: commits["2026.1"]},
		{input: commits["v1.2.3"], wantRef: commits["v1.2.3"], wantSHA: commits["v1.2.3"]},
		{input: "9.9.9", expectError: true},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			ref, sha, err := ResolveRef(ctx, repoDir, tc.input)
			if tc.expectError {
				if err == nil {
					t.Fatalf("expected error for %q, got ref=%q, sha=%q", tc.input, ref, sha)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for %q: %v", tc.input, err)
			}
			if ref != tc.wantRef {
				t.Errorf("ref = %q, want %q", ref, tc.wantRef)
			}
			if sha != tc.wantSHA {
				t.Errorf("sha = %q, want %q", sha, tc.wantSHA)
			}
		})
	}
}

func TestNewWorktree(t *testing.T) {
	repoDir, commits := setupTestGitRepo(t)
	ctx := context.Background()

	targetSHA := commits["v1.2.3"]
	wtPath, cleanup, err := NewWorktree(ctx, repoDir, targetSHA)
	if err != nil {
		t.Fatalf("NewWorktree failed: %v", err)
	}
	defer cleanup()

	// Verify worktree exists
	if fi, err := os.Stat(wtPath); err != nil || !fi.IsDir() {
		t.Fatalf("worktree path %s is not a directory: %v", wtPath, err)
	}

	// Verify content is from v1.2.3
	vFile := filepath.Join(wtPath, "version.txt")
	content, err := os.ReadFile(vFile)
	if err != nil {
		t.Fatalf("read version.txt in worktree: %v", err)
	}
	if string(content) != "v1.2.3" {
		t.Errorf("content = %q, want v1.2.3", string(content))
	}

	// Run cleanup and verify removal
	cleanup()
	if _, err := os.Stat(wtPath); !os.IsNotExist(err) {
		t.Errorf("expected worktree %s to be removed after cleanup", wtPath)
	}
}
