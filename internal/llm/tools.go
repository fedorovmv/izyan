package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/fix"
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/toolaudit"
	"example.com/vuln-analyzer/internal/vulnerability"
)

// ToolResult is what a tool returns to the model: structured content plus
// the evidence id it registered (if any). The model may cite evidence_ids
// in a claim; ids not present in the graph are discarded.
type ToolResult struct {
	OK         bool              `json:"ok"`
	EvidenceID domain.EvidenceID `json:"evidence_id,omitempty"`
	Content    json.RawMessage   `json:"content"`
	Error      string            `json:"error,omitempty"`
}

// Tools wraps the deterministic analyzers as typed tools for the agent
// loop. Every call is budgeted and its output registered as evidence.
// run_build / run_tests execute repository code and are gated by
// AllowExec; external process calls go through toolaudit so a case-level
// recorder captures them in tool_executions.
type Tools struct {
	Source      *goanalysis.Index
	Vuln        vulnerability.Source // get_advisory
	Patch       fix.Provider         // get_fix_diff
	Govulncheck goanalysis.Runner    // run_govulncheck
	GoTool      affected.GoTool      // get_module_version / get_dependency_graph
	AllowExec   bool                 // run_build / run_tests
}

// toolSchemas are advertised to the model.
const toolSchemas = `
read_function {"file":"<path>","function":"<name>"} -> source snippet
read_source {"file":"<path>","start":<line>,"end":<line>} -> raw source lines (0/0 = whole file; repository or Go module cache)
search_source {"pattern":"<regexp>"} -> matching "file:line: text" in product and dependency sources
find_symbol {"package":"<path>","symbol":"<Func|Type.Method>"} -> declaration site
find_references {"package":"<path>","symbol":"..."} -> references to the symbol
find_callers {"package":"<path>","symbol":"..."} -> call sites of the symbol
find_entrypoints {} -> product entrypoints
trace_argument {"file":"...","line":<n>,"column":<n>,"arg_index":<n>} -> dataflow origin of one call argument (-1 = all)
find_validations {"file":"...","line":<n>,"column":<n>,"arg_index":<n>} -> validation guards before the call
scan_dynamic {"package":"<path>","symbol":"..."} -> dynamic dispatch markers near the symbol
get_vulnerability {} -> normalized vulnerability record under analysis
get_advisory {"id":"<osv-id>"} -> advisory document
get_fix_references {} -> fix-bearing references (commits/patches) for the vulnerability
get_fix_diff {"url":"<reference>"} -> fetched patch text for a fix reference
get_module_version {"module":"<path>"} -> resolved version of a dependency module
get_dependency_graph {} -> module list with resolved versions
run_govulncheck {} -> findings for this vulnerability plus symbol coverage
run_build {} -> "go build ./..." result (requires exec permission)
run_tests {} -> "go test ./..." result (requires exec permission)`

// Schemas returns the human/tool-readable schema block for prompts.
func (Tools) Schemas() string { return toolSchemas }

// Call executes one tool. The AnalysisCase receives the evidence record and
// usage counters; results never fabricate facts — a tool miss is returned
// to the model as an error string, not as "no evidence exists".
func (t Tools) Call(ctx context.Context, c *domain.AnalysisCase, name string, args json.RawMessage) ToolResult {
	if c.UsageSnapshot().ToolCalls >= c.Workflow.Limits.MaxToolCalls && c.Workflow.Limits.MaxToolCalls > 0 {
		return ToolResult{Error: "tool call budget exhausted"}
	}
	c.IncToolCalls()

	fail := func(err error) ToolResult { return ToolResult{Error: err.Error()} }
	switch name {
	case "read_function":
		var a struct {
			File     string `json:"file"`
			Function string `json:"function"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		if c.UsageSnapshot().SourceReads >= c.Workflow.Limits.MaxSourceReads && c.Workflow.Limits.MaxSourceReads > 0 {
			return ToolResult{Error: "source read budget exhausted"}
		}
		c.IncSourceReads()
		src, err := t.Source.ReadFunction(ctx, a.File, a.Function)
		if err != nil {
			return fail(err)
		}
		id := addEvidence(c, domain.EvidenceSourceSnippet, "read_function", fmt.Sprintf("%s:%s", a.File, a.Function), src)
		return result(id, map[string]any{"file": a.File, "function": a.Function, "source": src})

	case "find_symbol":
		var a domain.SymbolRef
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		site, err := t.Source.FindSymbol(ctx, a)
		if err != nil {
			return fail(err)
		}
		id := addEvidence(c, domain.EvidenceSearchResult, "find_symbol", a.Package+"."+a.Symbol,
			fmt.Sprintf("declared at %s:%d", site.File, site.Line))
		return result(id, site)

	case "find_callers":
		var a domain.SymbolRef
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		sites, err := t.Source.FindCallers(ctx, a)
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(sites)
		id := addEvidence(c, domain.EvidenceCallPath, "find_callers", a.Package+"."+a.Symbol, string(b))
		return result(id, map[string]any{"call_sites": sites, "count": len(sites)})

	case "find_entrypoints":
		eps, err := t.Source.FindEntrypoints(ctx)
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(eps)
		id := addEvidence(c, domain.EvidenceEntrypoint, "find_entrypoints", "product entrypoints", string(b))
		return result(id, map[string]any{"entrypoints": eps})

	case "trace_argument":
		var a struct {
			File     string `json:"file"`
			Line     int    `json:"line"`
			Column   int    `json:"column"`
			ArgIndex int    `json:"arg_index"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		site := domain.CallSite{File: a.File, Line: a.Line, Column: a.Column}
		var flows []domain.DataFlow
		var evs []domain.Evidence
		var err error
		if a.ArgIndex < 0 {
			flows, evs, err = t.Source.TraceAllArguments(ctx, site)
		} else {
			var f domain.DataFlow
			f, evs, err = t.Source.TraceArgument(ctx, site, a.ArgIndex)
			flows = []domain.DataFlow{f}
		}
		if err != nil {
			return fail(err)
		}
		var last domain.EvidenceID
		for _, e := range evs {
			last = c.EvidenceGraph.AddEvidence(e)
		}
		for i := range flows {
			flows[i].ConditionID = condFromCtx(ctx)
		}
		c.EvidenceGraph.AddDataFlows(flows...)
		b, _ := json.Marshal(flows)
		id := addEvidence(c, domain.EvidenceDataFlow, "trace_argument",
			fmt.Sprintf("%s:%d", a.File, a.Line), string(b))
		if last != "" {
			id = last
		}
		return result(id, map[string]any{"data_flows": flows})

	case "find_validations":
		var a struct {
			File     string `json:"file"`
			Line     int    `json:"line"`
			Column   int    `json:"column"`
			ArgIndex int    `json:"arg_index"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		vals, evs, err := t.Source.FindValidations(ctx,
			domain.CallSite{File: a.File, Line: a.Line, Column: a.Column}, a.ArgIndex)
		if err != nil {
			return fail(err)
		}
		var last domain.EvidenceID
		for _, e := range evs {
			last = c.EvidenceGraph.AddEvidence(e)
		}
		c.EvidenceGraph.AddValidations(vals...)
		b, _ := json.Marshal(vals)
		id := addEvidence(c, domain.EvidenceValidation,
			"find_validations", fmt.Sprintf("%s:%d", a.File, a.Line), string(b))
		if last != "" {
			id = last
		}
		return result(id, map[string]any{"validations": vals})

	case "scan_dynamic":
		var a domain.SymbolRef
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		markers, err := t.Source.ScanDynamic(ctx, a)
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(markers)
		id := addEvidence(c, domain.EvidenceSearchResult, "scan_dynamic", a.Package+"."+a.Symbol, string(b))
		return result(id, map[string]any{"dynamic_markers": markers})

	case "find_references":
		var a domain.SymbolRef
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		sites, err := t.Source.SearchSymbol(ctx, a)
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(sites)
		id := addEvidence(c, domain.EvidenceSearchResult, "find_references", a.Package+"."+a.Symbol, string(b))
		return result(id, map[string]any{"references": sites, "count": len(sites)})

	case "read_source":
		var a struct {
			File  string `json:"file"`
			Start int    `json:"start"`
			End   int    `json:"end"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		if c.UsageSnapshot().SourceReads >= c.Workflow.Limits.MaxSourceReads && c.Workflow.Limits.MaxSourceReads > 0 {
			return ToolResult{Error: "source read budget exhausted"}
		}
		c.IncSourceReads()
		src, err := t.Source.ReadSource(ctx, a.File, a.Start, a.End)
		if err != nil {
			return fail(err)
		}
		id := addEvidence(c, domain.EvidenceSourceSnippet, "read_source", a.File, src)
		return result(id, map[string]any{"file": a.File, "source": src})

	case "search_source":
		var a struct {
			Pattern string `json:"pattern"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		matches, err := t.Source.SearchSource(ctx, a.Pattern)
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(matches)
		id := addEvidence(c, domain.EvidenceSearchResult, "search_source", a.Pattern, string(b))
		return result(id, map[string]any{"matches": matches, "count": len(matches)})

	case "get_vulnerability":
		b, _ := json.Marshal(c.Vulnerability)
		id := addEvidence(c, domain.EvidenceAdvisory, "get_vulnerability", c.Vulnerability.ID, string(b))
		return result(id, c.Vulnerability)

	case "get_advisory":
		var a struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		if t.Vuln == nil {
			return ToolResult{Error: "advisory source not configured"}
		}
		v, err := t.Vuln.Get(ctx, a.ID)
		if err != nil {
			return fail(err)
		}
		b, _ := json.Marshal(v)
		id := addEvidence(c, domain.EvidenceAdvisory, "get_advisory", v.ID, string(b))
		return result(id, v)

	case "get_fix_references":
		refs := (fix.Resolver{}).Resolve(c.Vulnerability)
		if len(refs) == 0 {
			return ToolResult{Error: "no fix-bearing references in the vulnerability record"}
		}
		b, _ := json.Marshal(refs)
		id := addEvidence(c, domain.EvidenceAdvisory, "get_fix_references", c.Vulnerability.ID, string(b))
		return result(id, map[string]any{"references": refs})

	case "get_fix_diff":
		var a struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		if t.Patch == nil {
			return ToolResult{Error: "patch provider not configured"}
		}
		text, err := t.Patch.Fetch(ctx, fix.Reference{URL: a.URL})
		if err != nil {
			return fail(err)
		}
		id := addEvidence(c, domain.EvidenceFixDiff, "get_fix_diff", a.URL, text)
		return result(id, map[string]any{"url": a.URL, "diff": text})

	case "get_module_version":
		var a struct {
			Module string `json:"module"`
		}
		if err := json.Unmarshal(args, &a); err != nil {
			return fail(err)
		}
		if a.Module == c.Vulnerability.Module && c.Affected != nil && c.Affected.ResolvedVersion != "" {
			return result("", map[string]any{"module": a.Module, "version": c.Affected.ResolvedVersion})
		}
		if t.GoTool == nil {
			return ToolResult{Error: "module lister not configured"}
		}
		raw, src, err := t.GoTool.ListModules(ctx, c.Product.Repository, c.Product)
		if err != nil {
			return fail(err)
		}
		mods, err := affected.DecodeModules(raw)
		if err != nil {
			return fail(err)
		}
		for _, m := range mods {
			if m.Path == a.Module {
				id := addEvidence(c, domain.EvidenceModuleGraph, "get_module_version:"+src, m.Path, string(raw))
				return result(id, map[string]any{"module": m.Path, "version": m.Version})
			}
		}
		return ToolResult{Error: "module " + a.Module + " not in the resolved dependency graph"}

	case "get_dependency_graph":
		if t.GoTool == nil {
			return ToolResult{Error: "module lister not configured"}
		}
		raw, src, err := t.GoTool.ListModules(ctx, c.Product.Repository, c.Product)
		if err != nil {
			return fail(err)
		}
		mods, err := affected.DecodeModules(raw)
		if err != nil {
			return fail(err)
		}
		id := addEvidence(c, domain.EvidenceModuleGraph, "get_dependency_graph:"+src, "module graph", string(raw))
		return result(id, map[string]any{"modules": mods, "source": src})

	case "run_govulncheck":
		if t.Govulncheck == nil {
			return ToolResult{Error: "govulncheck runner not configured"}
		}
		raw, gvErr := t.Govulncheck.RunGovulncheck(ctx, c.Product.Repository, c.Product)
		if gvErr != nil {
			return fail(fmt.Errorf("govulncheck: %w", gvErr))
		}
		res, err := goanalysis.Parse(raw)
		if err != nil {
			return fail(err)
		}
		var findings []goanalysis.Finding
		for _, f := range res.Findings {
			if f.OSV == c.Vulnerability.ID || contains(c.Vulnerability.Aliases, f.OSV) {
				findings = append(findings, f)
			}
		}
		b, _ := json.Marshal(findings)
		id := addEvidence(c, domain.EvidenceGovulncheck, "run_govulncheck", c.Vulnerability.ID, string(b))
		return result(id, map[string]any{
			"in_database": res.Covers(c.Vulnerability),
			"findings":    findings,
			"count":       len(findings),
		})

	case "run_build", "run_tests":
		if !t.AllowExec {
			return ToolResult{Error: name + " executes repository code and is disabled; pass --allow-exec to permit"}
		}
		sub := "build"
		if name == "run_tests" {
			sub = "test"
		}
		bin, env := t.goExec()
		stdout, stderr, err := toolaudit.Run(ctx, "go", "", c.Product.Repository, bin, env, sub, "./...")
		kind := domain.EvidenceBuild
		if name == "run_tests" {
			kind = domain.EvidenceTest
		}
		out := truncate(string(stdout), 8000)
		if err != nil {
			return ToolResult{OK: false, Error: fmt.Sprintf("go %s failed: %v: %s", sub, err, truncate(string(stderr), 2000)),
				EvidenceID: addEvidence(c, kind, name, "go "+sub+" ./...", out+truncate(string(stderr), 4000))}
		}
		id := addEvidence(c, kind, name, "go "+sub+" ./...", out)
		return result(id, map[string]any{"exit": 0, "output": out})
	}
	return ToolResult{Error: "unknown tool " + name}
}

// goExec returns the go binary and toolchain env for exec tools. The
// Env field carries PATH/GOTOOLCHAIN of the resolved case toolchain.
func (t Tools) goExec() (string, []string) {
	if t.Source != nil && len(t.Source.Env) > 0 {
		return "go", t.Source.Env
	}
	return "go", nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func addEvidence(c *domain.AnalysisCase, kind domain.EvidenceKind, tool, title, content string) domain.EvidenceID {
	return c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    kind,
		Quality: domain.QualityDeterministic,
		Source:  title,
		Tool:    "agent." + tool,
		Content: truncate(content, 4000),
	})
}

func result(id domain.EvidenceID, v any) ToolResult {
	b, err := json.Marshal(v)
	if err != nil {
		return ToolResult{Error: err.Error()}
	}
	return ToolResult{OK: true, EvidenceID: id, Content: b}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}

// condCtxKey carries the condition being evaluated so tool-produced
// evidence is tagged to it.
type ctxKey struct{ name string }

var condCtxKey = ctxKey{"cond"}

func withCond(ctx context.Context, id domain.ConditionID) context.Context {
	return context.WithValue(ctx, condCtxKey, id)
}

func condFromCtx(ctx context.Context) domain.ConditionID {
	if v, ok := ctx.Value(condCtxKey).(domain.ConditionID); ok {
		return v
	}
	return ""
}
