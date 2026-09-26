package llm

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/goanalysis"
)

type stubGoTool struct{ raw []byte }

func (s stubGoTool) ListModules(_ context.Context, _ string, _ domain.ProductSnapshot) ([]byte, string, error) {
	return s.raw, "go list -m", nil
}
func (s stubGoTool) ListPackages(_ context.Context, _ string, _ domain.ProductSnapshot) ([]byte, error) {
	return nil, nil
}

type stubRunner struct {
	raw []byte
	err error
}

func (s stubRunner) RunGovulncheck(_ context.Context, _ string, _ domain.ProductSnapshot) ([]byte, error) {
	return s.raw, s.err
}

type stubVulnSource struct{ v *domain.Vulnerability }

func (s stubVulnSource) Get(_ context.Context, id string) (*domain.Vulnerability, error) {
	s.v.ID = id
	return s.v, nil
}

func toolsCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID:      "GO-TEST-0001",
			Aliases: []string{"CVE-0000-0001"},
			Module:  "example.com/vuln",
			References: []domain.Reference{
				{Type: "ADVISORY", URL: "https://example.com/adv"},
				{Type: "FIX", URL: "https://github.com/x/vuln/commit/abc"},
			},
		},
	}
}

func toolIndex(t *testing.T) *goanalysis.Index {
	t.Helper()
	return &goanalysis.Index{Dir: filepath.Join("..", "..", "testdata", "constprod")}
}

func call(t *testing.T, tools Tools, c *domain.AnalysisCase, name, args string) ToolResult {
	t.Helper()
	return tools.Call(context.Background(), c, name, json.RawMessage(args))
}

func TestToolReadSourceConfined(t *testing.T) {
	tools := Tools{Source: toolIndex(t)}
	c := toolsCase()

	res := call(t, tools, c, "read_source", `{"file":"../../etc/passwd"}`)
	if res.Error == "" {
		t.Fatal("path escaping the repo must be rejected")
	}

	res = call(t, tools, c, "read_source", `{"file":"main.go","start":1,"end":3}`)
	if res.Error != "" || !strings.Contains(string(res.Content), "package") {
		t.Fatalf("in-repo range read failed: %+v", res)
	}
}

func TestToolSearchSource(t *testing.T) {
	tools := Tools{Source: toolIndex(t)}
	res := call(t, tools, toolsCase(), "search_source", `{"pattern":"vuln\\.Parse"}`)
	if res.Error != "" || !strings.Contains(string(res.Content), "vuln.Parse") {
		t.Fatalf("search_source: %+v", res)
	}
	res = call(t, tools, toolsCase(), "search_source", `{"pattern":"[broken"}`)
	if res.Error == "" {
		t.Fatal("bad regex must surface as an error")
	}
}

func TestToolFindReferences(t *testing.T) {
	tools := Tools{Source: toolIndex(t)}
	res := call(t, tools, toolsCase(), "find_references",
		`{"package":"example.com/dep/vuln","symbol":"Parse"}`)
	if res.Error != "" || !strings.Contains(string(res.Content), "main.go") {
		t.Fatalf("find_references: %+v", res)
	}
}

func TestToolGetVulnerabilityAndFixRefs(t *testing.T) {
	tools := Tools{Source: toolIndex(t)}
	c := toolsCase()

	res := call(t, tools, c, "get_vulnerability", `{}`)
	if res.Error != "" || !strings.Contains(string(res.Content), "GO-TEST-0001") {
		t.Fatalf("get_vulnerability: %+v", res)
	}

	res = call(t, tools, c, "get_fix_references", `{}`)
	if res.Error != "" || !strings.Contains(string(res.Content), "commit/abc") {
		t.Fatalf("get_fix_references: %+v", res)
	}

	c.Vulnerability.References = nil
	res = call(t, tools, c, "get_fix_references", `{}`)
	if res.Error == "" {
		t.Fatal("no fix refs must be a tool miss, not fabricated data")
	}
}

func TestToolGetAdvisory(t *testing.T) {
	v := &domain.Vulnerability{ID: "placeholder"}
	tools := Tools{Source: toolIndex(t), Vuln: stubVulnSource{v: v}}
	res := call(t, tools, toolsCase(), "get_advisory", `{"id":"GHSA-xxxx"}`)
	if res.Error != "" || !strings.Contains(string(res.Content), "GHSA-xxxx") {
		t.Fatalf("get_advisory: %+v", res)
	}
	res = call(t, Tools{Source: toolIndex(t)}, toolsCase(), "get_advisory", `{"id":"X"}`)
	if res.Error == "" {
		t.Fatal("unconfigured advisory source must error")
	}
}

func TestToolModuleVersionAndGraph(t *testing.T) {
	raw := []byte(`{"Path":"example.com/vuln","Version":"v1.2.3"}
{"Path":"example.com/prod","Version":"v0.0.0","Main":true}
`)
	tools := Tools{Source: toolIndex(t), GoTool: stubGoTool{raw: raw}}
	c := toolsCase()
	c.Product.Repository = "."
	c.Affected = &domain.AffectedResult{ResolvedVersion: "v1.2.3"}

	res := call(t, tools, c, "get_module_version", `{"module":"example.com/vuln"}`)
	if res.Error != "" || !strings.Contains(string(res.Content), "v1.2.3") {
		t.Fatalf("resolved version: %+v", res)
	}

	res = call(t, tools, c, "get_dependency_graph", `{}`)
	if res.Error != "" || !strings.Contains(string(res.Content), "example.com/prod") {
		t.Fatalf("dependency graph: %+v", res)
	}

	res = call(t, tools, c, "get_module_version", `{"module":"example.com/missing"}`)
	if res.Error == "" {
		t.Fatal("absent module must be a tool miss")
	}
}

func TestToolRunGovulncheck(t *testing.T) {
	gv := `{"config":{"mode":"source"},"progress":{"message":"x"}}
{"osv":{"id":"GO-TEST-0001"},"finding":{"osv":"GO-TEST-0001","trace":[{"function":"main.main"}]}}
`
	tools := Tools{
		Source:      toolIndex(t),
		Govulncheck: stubRunner{raw: []byte(gv)},
	}
	c := toolsCase()
	c.Product.Repository = "."

	res := call(t, tools, c, "run_govulncheck", `{}`)
	if res.Error != "" {
		t.Fatalf("run_govulncheck: %s", res.Error)
	}
	if !strings.Contains(string(res.Content), `"count":1`) {
		t.Fatalf("expected one finding for the case vuln: %s", res.Content)
	}
}

func TestToolExecGated(t *testing.T) {
	tools := Tools{Source: toolIndex(t)}
	c := toolsCase()
	for _, name := range []string{"run_build", "run_tests"} {
		res := call(t, tools, c, name, `{}`)
		if res.Error == "" || !strings.Contains(res.Error, "disabled") {
			t.Fatalf("%s must be gated without AllowExec: %+v", name, res)
		}
	}
}
