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
