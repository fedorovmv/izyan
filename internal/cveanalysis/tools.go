package cveanalysis

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/llm"
)

type ToolRunner interface {
	Call(ctx context.Context, caseData *domain.AnalysisCase, toolName string, args json.RawMessage) llm.ToolResult
}

type DefaultToolRunner struct {
	scopeAnalyzer *ScopeAnalyzer
}

func NewToolRunner() *DefaultToolRunner {
	return &DefaultToolRunner{
		scopeAnalyzer: NewScopeAnalyzer(),
	}
}

func (r *DefaultToolRunner) Call(ctx context.Context, caseData *domain.AnalysisCase, toolName string, args json.RawMessage) llm.ToolResult {
	switch toolName {
	case "read_patch_diff":
		if caseData.CVEAnalysisBundle == nil || caseData.CVEAnalysisBundle.PatchDiff == "" {
			return llm.ToolResult{OK: false, Error: "no patch diff available in bundle"}
		}
		raw, _ := json.Marshal(caseData.CVEAnalysisBundle.PatchDiff)
		return llm.ToolResult{OK: true, Content: raw}

	case "inspect_source_file":
		var p struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
		}
		if err := json.Unmarshal(args, &p); err != nil {
			return llm.ToolResult{OK: false, Error: fmt.Sprintf("invalid args: %v", err)}
		}
		if caseData.CVEAnalysisBundle == nil || caseData.CVEAnalysisBundle.SourceDir == "" {
			return llm.ToolResult{OK: false, Error: "no source directory available in bundle"}
		}

		cleanSourceDir := filepath.Clean(caseData.CVEAnalysisBundle.SourceDir)
		var fullPath string
		if filepath.IsAbs(p.Path) {
			fullPath = filepath.Clean(p.Path)
		} else {
			fullPath = filepath.Clean(filepath.Join(cleanSourceDir, p.Path))
		}
		rel, err := filepath.Rel(cleanSourceDir, fullPath)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return llm.ToolResult{OK: false, Error: "path escapes source directory"}
		}

		// Budget check
		if caseData.Workflow.Limits.MaxSourceReads > 0 &&
			caseData.UsageSnapshot().SourceReads >= caseData.Workflow.Limits.MaxSourceReads {
			return llm.ToolResult{OK: false, Error: "MaxSourceReads limit reached"}
		}
		caseData.IncSourceReads()

		f, err := os.Open(fullPath)
		if err != nil {
			return llm.ToolResult{OK: false, Error: fmt.Sprintf("failed to open file: %v", err)}
		}
		defer f.Close()

		var lines []string
		scanner := bufio.NewScanner(f)
		lineNum := 1
		for scanner.Scan() {
			if (p.StartLine == 0 || lineNum >= p.StartLine) && (p.EndLine == 0 || lineNum <= p.EndLine) {
				lines = append(lines, scanner.Text())
			}
			lineNum++
		}
		raw, _ := json.Marshal(strings.Join(lines, "\n"))
		return llm.ToolResult{OK: true, Content: raw}

	default:
		return llm.ToolResult{OK: false, Error: fmt.Sprintf("unknown tool %s", toolName)}
	}
}
