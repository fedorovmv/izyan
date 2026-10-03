package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_LLMIntakeValidation(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "ticket.txt")
	if err := os.WriteFile(tmpFile, []byte("Vuln GO-2026-6443 in locuslib"), 0o644); err != nil {
		t.Fatal(err)
	}

	repoPath := filepath.Join("..", "..", "testdata", "locuslib")
	cmd := exec.Command("go", "run", ".", "analyze",
		"--repo", repoPath,
		"--ticket", tmpFile,
		"--llm-intake",
		"--deterministic-only",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected command to fail when mixing --llm-intake with --deterministic-only")
	}
	if !strings.Contains(string(out), "--llm-intake: cannot use --llm-intake") {
		t.Fatalf("expected error message about --llm-intake, got: %s", string(out))
	}
}

func TestCLI_TicketDeterministicIntake(t *testing.T) {
	repoPath := filepath.Join("..", "..", "testdata", "locuslib")
	if _, err := os.Stat(repoPath); err != nil {
		t.Skip("fixture repo not found")
	}

	tmpDir := t.TempDir()
	caseDir := filepath.Join(tmpDir, "case")
	tmpTicket := filepath.Join(tmpDir, "ticket.txt")
	vulnFile := filepath.Join("..", "..", "eval", "advisories", "real", "GO-2026-6443.json")

	ticketContent := `Ticket: SEC-101
Vulnerability: GO-2026-6443
Component: locuslib
`
	if err := os.WriteFile(tmpTicket, []byte(ticketContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("go", "run", ".", "analyze",
		"--repo", repoPath,
		"--ticket", tmpTicket,
		"--vuln-file", vulnFile,
		"--case-dir", caseDir,
		"--deterministic-only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v, output: %s", err, string(out))
	}

	matches, err := filepath.Glob(filepath.Join(caseDir, "*", "report.md"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("failed to find report.md in %s, matches: %v, out: %s", caseDir, matches, string(out))
	}

	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("failed to read report.md: %v", err)
	}

	if !strings.Contains(string(data), "GO-2026-6443") {
		t.Errorf("report missing vulnerability ID")
	}
	if !strings.Contains(string(data), "SEC-101") {
		t.Errorf("report missing ticket ID SEC-101")
	}
}

func TestCLI_CheckoutReleaseWorktree(t *testing.T) {
	repoDir := t.TempDir()

	gitRun := func(args ...string) {
		cmd := exec.Command("git", args...)
		cmd.Dir = repoDir
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

	gitRun("init", "-b", "main")
	gitRun("config", "user.name", "Test")
	gitRun("config", "user.email", "test@example.com")

	// Commit 1: v1.0.0
	if err := os.WriteFile(filepath.Join(repoDir, "go.mod"), []byte("module example.com/testmod\n\ngo 1.22\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repoDir, "version.txt"), []byte("1.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun("add", ".")
	gitRun("commit", "-m", "release 1.0.0")
	gitRun("tag", "v1.0.0")

	outSHA1, _ := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD").Output()
	sha1 := strings.TrimSpace(string(outSHA1))

	// Commit 2: v2.0.0
	if err := os.WriteFile(filepath.Join(repoDir, "version.txt"), []byte("2.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitRun("add", "version.txt")
	gitRun("commit", "-m", "release 2.0.0")
	gitRun("tag", "v2.0.0")

	outSHA2, _ := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD").Output()
	sha2 := strings.TrimSpace(string(outSHA2))

	tmpDir := t.TempDir()
	caseDir := filepath.Join(tmpDir, "case")
	tmpTicket := filepath.Join(tmpDir, "ticket.txt")
	vulnFile := filepath.Join("..", "..", "eval", "advisories", "real", "GO-2026-6443.json")

	ticketContent := `Ticket: REL-999
Vulnerability: GO-2026-6443
Component: testmod
Release: 1.0.0
`
	if err := os.WriteFile(tmpTicket, []byte(ticketContent), 0o644); err != nil {
		t.Fatal(err)
	}

	// Run analyze with --checkout-release
	cmd := exec.Command("go", "run", ".", "analyze",
		"--repo", repoDir,
		"--ticket", tmpTicket,
		"--checkout-release",
		"--vuln-file", vulnFile,
		"--case-dir", caseDir,
		"--deterministic-only",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v, output: %s", err, string(out))
	}

	// 1. Verify main repo HEAD is still sha2 (unmodified by checkout)
	headOut, _ := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD").Output()
	if strings.TrimSpace(string(headOut)) != sha2 {
		t.Errorf("main repo HEAD was mutated: got %s, want %s", strings.TrimSpace(string(headOut)), sha2)
	}

	// 2. Verify git worktree list has no lingering worktree
	wtListOut, _ := exec.Command("git", "-C", repoDir, "worktree", "list", "--porcelain").Output()
	if strings.Count(string(wtListOut), "worktree ") != 1 {
		t.Errorf("expected 1 worktree in list, got:\n%s", string(wtListOut))
	}

	// 3. Verify case report recorded the release checkout and snapshot commit
	matches, err := filepath.Glob(filepath.Join(caseDir, "*", "report.json"))
	if err != nil || len(matches) == 0 {
		t.Fatalf("failed to find report.json in %s", caseDir)
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	// Case snapshot commit should be sha1, not sha2!
	if !strings.Contains(string(data), sha1) {
		t.Errorf("report.json does not contain commit %s from release 1.0.0 (got data: %s)", sha1, string(data))
	}
	if strings.Contains(string(data), sha2) {
		t.Errorf("report.json should NOT contain commit %s from HEAD release 2.0.0", sha2)
	}
}

func TestCLI_CheckoutReleaseValidation(t *testing.T) {
	repoPath := filepath.Join("..", "..", "testdata", "locuslib")
	vulnFile := filepath.Join("..", "..", "eval", "advisories", "real", "GO-2026-6443.json")

	// Missing release with --checkout-release
	cmd := exec.Command("go", "run", ".", "analyze",
		"--repo", repoPath,
		"--vuln", "GO-2026-6443",
		"--vuln-file", vulnFile,
		"--checkout-release",
		"--deterministic-only",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error when --checkout-release is given without release")
	}
	if !strings.Contains(string(out), "no release specified") {
		t.Fatalf("expected error to mention 'no release specified', got: %s", string(out))
	}
}
