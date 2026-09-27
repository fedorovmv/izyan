package toolaudit

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestDiffExecutions(t *testing.T) {
	prev := []domain.ToolExecution{
		{Tool: "go", Dir: "/r", Args: []string{"version"}, ExitCode: 0, StdoutSHA256: "a", StderrSHA256: "e"},
		{Tool: "go", Dir: "/r", Args: []string{"list"}, ExitCode: 0, StdoutSHA256: "b", StderrSHA256: "e"},
	}
	cur := []domain.ToolExecution{
		{Tool: "go", Dir: "/r", Args: []string{"version"}, ExitCode: 0, StdoutSHA256: "a", StderrSHA256: "e"},
		{Tool: "go", Dir: "/r", Args: []string{"list"}, ExitCode: 1, StdoutSHA256: "c", StderrSHA256: "e"},
		{Tool: "govulncheck", Dir: "/r", Args: []string{"-version"}, ExitCode: 0, StdoutSHA256: "x"},
	}
	got := DiffExecutions(prev, cur)
	if len(got) != 2 {
		t.Fatalf("drift=%v", got)
	}
	t.Log(got)
	if d := DiffExecutions(cur, cur); len(d) != 0 {
		t.Fatalf("self-diff must be empty: %v", d)
	}
}
