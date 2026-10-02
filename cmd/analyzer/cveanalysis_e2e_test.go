package main_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLI_CVEAnalysisAssistProfile(t *testing.T) {
	tmpDir := t.TempDir()
	caseDir := filepath.Join(tmpDir, "case")

	repoPath := filepath.Join("..", "..", "testdata", "locuslib")
	if _, err := os.Stat(repoPath); err != nil {
		t.Skip("fixture repo not found")
	}

	vulnFile := filepath.Join("..", "..", "eval", "advisories", "real", "GO-2026-6443.json")

	cmd := exec.Command("go", "run", ".", "analyze",
		"--repo", repoPath,
		"--vuln", "GO-2026-6443",
		"--vuln-file", vulnFile,
		"--case-dir", caseDir,
		"--cve-analysis=assist",
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
}

func TestCLI_StrictLLMValidation(t *testing.T) {
	repoPath := filepath.Join("..", "..", "testdata", "locuslib")
	cmd := exec.Command("go", "run", ".", "analyze",
		"--repo", repoPath,
		"--vuln", "GO-2026-6443",
		"--strict-llm",
		"--deterministic-only",
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected command to fail when mixing --strict-llm with --deterministic-only")
	}
	if !strings.Contains(string(out), "strict-llm: cannot use --strict-llm") {
		t.Fatalf("expected error message about strict-llm, got: %s", string(out))
	}
}

func TestCLI_CVEAnalysisVerifiedProfile(t *testing.T) {
	tmpDir := t.TempDir()
	caseDir := filepath.Join(tmpDir, "case")

	repoPath := filepath.Join("..", "..", "testdata", "locuslib")
	if _, err := os.Stat(repoPath); err != nil {
		t.Skip("fixture repo not found")
	}

	vulnFile := filepath.Join("..", "..", "eval", "advisories", "real", "GO-2026-6443.json")

	cmd := exec.Command("go", "run", ".", "analyze",
		"--repo", repoPath,
		"--vuln", "GO-2026-6443",
		"--vuln-file", vulnFile,
		"--case-dir", caseDir,
		"--cve-analysis=verified",
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
}
