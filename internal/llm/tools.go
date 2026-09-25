package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/goanalysis"
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

// Tools wraps the deterministic source index as typed tools for the agent
// loop. Every call is budgeted and its output registered as evidence.
type Tools struct {
	Source *goanalysis.Index
}

// toolSchemas are advertised to the model.
const toolSchemas = `
read_function {"file":"<path>","function":"<name>"} -> source snippet
find_symbol {"package":"<path>","symbol":"<Func|Type.Method>"} -> declaration site
find_callers {"package":"<path>","symbol":"..."} -> call sites of the symbol
find_entrypoints {} -> product entrypoints
trace_argument {"file":"...","line":<n>,"column":<n>,"arg_index":<n>} -> dataflow origin of one call argument (-1 = all)
find_validations {"file":"...","line":<n>,"column":<n>,"arg_index":<n>} -> validation guards before the call
scan_dynamic {"package":"<path>","symbol":"..."} -> dynamic dispatch markers near the symbol`

// Schemas returns the human/tool-readable schema block for prompts.
func (Tools) Schemas() string { return toolSchemas }

// Call executes one tool. The AnalysisCase receives the evidence record and
// usage counters; results never fabricate facts — a tool miss is returned
// to the model as an error string, not as "no evidence exists".
func (t Tools) Call(ctx context.Context, c *domain.AnalysisCase, name string, args json.RawMessage) ToolResult {
	if c.Workflow.Usage.ToolCalls >= c.Workflow.Limits.MaxToolCalls && c.Workflow.Limits.MaxToolCalls > 0 {
		return ToolResult{Error: "tool call budget exhausted"}
	}
	c.Workflow.Usage.ToolCalls++

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
		if c.Workflow.Usage.SourceReads >= c.Workflow.Limits.MaxSourceReads && c.Workflow.Limits.MaxSourceReads > 0 {
			return ToolResult{Error: "source read budget exhausted"}
		}
		c.Workflow.Usage.SourceReads++
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
		c.EvidenceGraph.DataFlows = append(c.EvidenceGraph.DataFlows, flows...)
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
		c.EvidenceGraph.Validations = append(c.EvidenceGraph.Validations, vals...)
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
	}
	return ToolResult{Error: "unknown tool " + name}
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
