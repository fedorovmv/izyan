package cveanalysis_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/cveanalysis"
	"github.com/fedorovmv/izyan/internal/domain"
)

func TestToolRunner_PathTraversalBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}

	secretFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("password123"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create adjacent sibling directory like /tmp/src-evil
	siblingDir := filepath.Join(tmpDir, "src-evil")
	if err := os.MkdirAll(siblingDir, 0755); err != nil {
		t.Fatal(err)
	}
	siblingSecret := filepath.Join(siblingDir, "evil-secret.txt")
	if err := os.WriteFile(siblingSecret, []byte("evil123"), 0644); err != nil {
		t.Fatal(err)
	}

	runner := cveanalysis.NewToolRunner()
	caseData := &domain.AnalysisCase{
		CVEAnalysisBundle: &domain.CVESourceBundle{
			SourceDir: srcDir,
		},
	}

	testCases := []struct {
		name string
		path string
	}{
		{
			name: "parent traversal",
			path: "../secret.txt",
		},
		{
			name: "deep parent traversal",
			path: "../../../../secret.txt",
		},
		{
			name: "sibling directory via relative traversal",
			path: "../src-evil/evil-secret.txt",
		},
		{
			name: "absolute path escaping source dir",
			path: secretFile,
		},
		{
			name: "absolute path to sibling directory",
			path: siblingSecret,
		},
		{
			name: "absolute path to root/etc",
			path: "/etc/passwd",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			args, err := json.Marshal(map[string]interface{}{
				"path": tc.path,
			})
			if err != nil {
				t.Fatalf("failed to marshal args: %v", err)
			}

			res := runner.Call(context.Background(), caseData, "inspect_source_file", args)
			if res.OK {
				t.Fatalf("expected path traversal to fail for %q, got OK=true: %s", tc.path, string(res.Content))
			}
			if res.Error != "path escapes source directory" {
				t.Fatalf("expected error 'path escapes source directory', got %q", res.Error)
			}
		})
	}
}

func TestToolRunner_InspectSourceFile_Success(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(filepath.Join(srcDir, "pkg"), 0755); err != nil {
		t.Fatal(err)
	}

	content := "line 1\nline 2\nline 3\nline 4\nline 5\n"
	targetFile := filepath.Join(srcDir, "pkg", "sample.go")
	if err := os.WriteFile(targetFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	runner := cveanalysis.NewToolRunner()
	caseData := &domain.AnalysisCase{
		CVEAnalysisBundle: &domain.CVESourceBundle{
			SourceDir: srcDir,
		},
	}

	// 1. Read entire file (start_line=0, end_line=0)
	argsAll, _ := json.Marshal(map[string]interface{}{
		"path": "pkg/sample.go",
	})
	resAll := runner.Call(context.Background(), caseData, "inspect_source_file", argsAll)
	if !resAll.OK {
		t.Fatalf("expected success, got error: %s", resAll.Error)
	}

	var textAll string
	if err := json.Unmarshal(resAll.Content, &textAll); err != nil {
		t.Fatalf("failed to unmarshal content: %v", err)
	}
	expectedAll := strings.TrimRight(content, "\n")
	if textAll != expectedAll {
		t.Fatalf("expected:\n%s\ngot:\n%s", expectedAll, textAll)
	}

	if caseData.UsageSnapshot().SourceReads != 1 {
		t.Fatalf("expected SourceReads=1, got %d", caseData.UsageSnapshot().SourceReads)
	}

	// 2. Read specific line range (lines 2 to 4)
	argsRange, _ := json.Marshal(map[string]interface{}{
		"path":       "pkg/sample.go",
		"start_line": 2,
		"end_line":   4,
	})
	resRange := runner.Call(context.Background(), caseData, "inspect_source_file", argsRange)
	if !resRange.OK {
		t.Fatalf("expected range read success, got error: %s", resRange.Error)
	}

	var textRange string
	if err := json.Unmarshal(resRange.Content, &textRange); err != nil {
		t.Fatalf("failed to unmarshal content: %v", err)
	}
	expectedRange := "line 2\nline 3\nline 4"
	if textRange != expectedRange {
		t.Fatalf("expected %q, got %q", expectedRange, textRange)
	}

	if caseData.UsageSnapshot().SourceReads != 2 {
		t.Fatalf("expected SourceReads=2, got %d", caseData.UsageSnapshot().SourceReads)
	}
}

func TestToolRunner_InspectSourceFile_BudgetExceeded(t *testing.T) {
	tmpDir := t.TempDir()
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "sample.go"), []byte("package main\n"), 0644); err != nil {
		t.Fatal(err)
	}

	runner := cveanalysis.NewToolRunner()
	caseData := &domain.AnalysisCase{
		CVEAnalysisBundle: &domain.CVESourceBundle{
			SourceDir: srcDir,
		},
		Workflow: domain.WorkflowStatus{
			Limits: domain.AnalysisLimits{
				MaxSourceReads: 2,
			},
		},
	}

	args, _ := json.Marshal(map[string]interface{}{
		"path": "sample.go",
	})

	// Read 1
	r1 := runner.Call(context.Background(), caseData, "inspect_source_file", args)
	if !r1.OK {
		t.Fatalf("call 1 failed: %s", r1.Error)
	}

	// Read 2
	r2 := runner.Call(context.Background(), caseData, "inspect_source_file", args)
	if !r2.OK {
		t.Fatalf("call 2 failed: %s", r2.Error)
	}

	// Read 3 - budget exceeded
	r3 := runner.Call(context.Background(), caseData, "inspect_source_file", args)
	if r3.OK {
		t.Fatal("call 3 should fail due to MaxSourceReads budget")
	}
	if r3.Error != "MaxSourceReads limit reached" {
		t.Fatalf("expected 'MaxSourceReads limit reached', got %q", r3.Error)
	}
	if caseData.UsageSnapshot().SourceReads != 2 {
		t.Fatalf("SourceReads should remain 2, got %d", caseData.UsageSnapshot().SourceReads)
	}
}

func TestToolRunner_InspectSourceFile_Errors(t *testing.T) {
	runner := cveanalysis.NewToolRunner()

	// Missing bundle
	caseNoBundle := &domain.AnalysisCase{}
	r1 := runner.Call(context.Background(), caseNoBundle, "inspect_source_file", []byte(`{"path":"a.go"}`))
	if r1.OK || r1.Error != "no source directory available in bundle" {
		t.Fatalf("expected 'no source directory available in bundle', got ok=%v, err=%q", r1.OK, r1.Error)
	}

	// Empty source dir
	caseEmptyDir := &domain.AnalysisCase{
		CVEAnalysisBundle: &domain.CVESourceBundle{
			SourceDir: "",
		},
	}
	r2 := runner.Call(context.Background(), caseEmptyDir, "inspect_source_file", []byte(`{"path":"a.go"}`))
	if r2.OK || r2.Error != "no source directory available in bundle" {
		t.Fatalf("expected 'no source directory available in bundle', got ok=%v, err=%q", r2.OK, r2.Error)
	}

	// Invalid args
	caseValid := &domain.AnalysisCase{
		CVEAnalysisBundle: &domain.CVESourceBundle{
			SourceDir: t.TempDir(),
		},
	}
	r3 := runner.Call(context.Background(), caseValid, "inspect_source_file", []byte(`{invalid}`))
	if r3.OK || !strings.HasPrefix(r3.Error, "invalid args:") {
		t.Fatalf("expected invalid args error, got ok=%v, err=%q", r3.OK, r3.Error)
	}

	// File not found
	r4 := runner.Call(context.Background(), caseValid, "inspect_source_file", []byte(`{"path":"nonexistent.go"}`))
	if r4.OK || !strings.HasPrefix(r4.Error, "failed to open file:") {
		t.Fatalf("expected failed to open file error, got ok=%v, err=%q", r4.OK, r4.Error)
	}
}

func TestToolRunner_ReadPatchDiff(t *testing.T) {
	runner := cveanalysis.NewToolRunner()

	// Missing bundle
	caseNoBundle := &domain.AnalysisCase{}
	r1 := runner.Call(context.Background(), caseNoBundle, "read_patch_diff", nil)
	if r1.OK || r1.Error != "no patch diff available in bundle" {
		t.Fatalf("expected 'no patch diff available in bundle', got ok=%v, err=%q", r1.OK, r1.Error)
	}

	// Empty diff
	caseEmptyDiff := &domain.AnalysisCase{
		CVEAnalysisBundle: &domain.CVESourceBundle{
			PatchDiff: "",
		},
	}
	r2 := runner.Call(context.Background(), caseEmptyDiff, "read_patch_diff", nil)
	if r2.OK || r2.Error != "no patch diff available in bundle" {
		t.Fatalf("expected 'no patch diff available in bundle', got ok=%v, err=%q", r2.OK, r2.Error)
	}

	// Success
	expectedDiff := "diff --git a/foo.go b/foo.go\n--- a/foo.go\n+++ b/foo.go\n@@ -1 +1 @@\n-old\n+new\n"
	caseWithDiff := &domain.AnalysisCase{
		CVEAnalysisBundle: &domain.CVESourceBundle{
			PatchDiff: expectedDiff,
		},
	}
	r3 := runner.Call(context.Background(), caseWithDiff, "read_patch_diff", nil)
	if !r3.OK {
		t.Fatalf("expected success, got error: %s", r3.Error)
	}
	var returnedDiff string
	if err := json.Unmarshal(r3.Content, &returnedDiff); err != nil {
		t.Fatalf("failed to unmarshal content: %v", err)
	}
	if returnedDiff != expectedDiff {
		t.Fatalf("expected %q, got %q", expectedDiff, returnedDiff)
	}
}

func TestToolRunner_UnknownTool(t *testing.T) {
	runner := cveanalysis.NewToolRunner()
	caseData := &domain.AnalysisCase{}
	res := runner.Call(context.Background(), caseData, "non_existent_tool", nil)
	if res.OK {
		t.Fatal("expected failure for unknown tool")
	}
	if res.Error != "unknown tool non_existent_tool" {
		t.Fatalf("expected 'unknown tool non_existent_tool', got %q", res.Error)
	}
}
