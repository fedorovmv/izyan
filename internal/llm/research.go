package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Completer abstracts LLM chat completion.
type Completer interface {
	Complete(ctx context.Context, role ModelRole, system, user string) (string, string, error)
}

// NativeToolCompleter is implemented by clients supporting OpenAI native tool calling.
type NativeToolCompleter interface {
	Chat(ctx context.Context, role ModelRole, system string, messages []ChatMessage, tools []ToolDefinition) (ChatMessage, string, error)
}

// ResearchToolRunner abstracts tool execution for the researcher.
type ResearchToolRunner interface {
	Call(ctx context.Context, caseData *domain.AnalysisCase, toolName string, args json.RawMessage) ToolResult
}

// Researcher conducts bounded CVE analysis using tools and an LLM client.
type Researcher struct {
	client  Completer
	tools   ResearchToolRunner
	maxIter int
}

// NewResearcher constructs a Researcher with a bounded iteration limit (max 8).
func NewResearcher(client Completer, tools ResearchToolRunner, maxIter int) *Researcher {
	if maxIter <= 0 || maxIter > 8 {
		maxIter = 8
	}
	return &Researcher{client: client, tools: tools, maxIter: maxIter}
}

var researchToolDefinitions = []ToolDefinition{
	{
		Type: "function",
		Function: FunctionSpec{
			Name:        "read_patch_diff",
			Description: "Read the git patch diff for the vulnerability fix",
			Parameters:  json.RawMessage(`{"type":"object","properties":{}}`),
		},
	},
	{
		Type: "function",
		Function: FunctionSpec{
			Name:        "inspect_source_file",
			Description: "Inspect lines of code from a file in the dependency repository",
			Parameters: json.RawMessage(`{
				"type":"object",
				"properties":{
					"path":{"type":"string","description":"relative path in dependency repository"},
					"start_line":{"type":"integer","description":"1-indexed start line"},
					"end_line":{"type":"integer","description":"1-indexed end line"}
				},
				"required":["path"]
			}`),
		},
	},
	{
		Type: "function",
		Function: FunctionSpec{
			Name:        "analyze_product_scope",
			Description: "Analyze whether a symbol is directly called in the product code",
			Parameters: json.RawMessage(`{
				"type":"object",
				"properties":{
					"symbol":{"type":"string","description":"symbol reference (package.Symbol or Type.Method)"}
				},
				"required":["symbol"]
			}`),
		},
	},
}

type researcherStep struct {
	Action   string                      `json:"action"` // "tool" or "final"
	Tool     string                      `json:"tool,omitempty"`
	Args     json.RawMessage             `json:"args,omitempty"`
	Proposal *domain.CVEAnalysisProposal `json:"proposal,omitempty"`
}

// Research drives the bounded research loop to isolate faulting sites and auxiliary sites.
func (r *Researcher) Research(ctx context.Context, caseData *domain.AnalysisCase) (domain.CVEAnalysisProposal, error) {
	proposal := domain.CVEAnalysisProposal{
		ID:         fmt.Sprintf("PROP-%s", caseData.Vulnerability.ID),
		Confidence: "LOW",
	}

	if r.client == nil {
		return proposal, fmt.Errorf("llm client unavailable")
	}

	if tc, ok := r.client.(NativeToolCompleter); ok {
		return r.researchNative(ctx, caseData, tc)
	}
	return r.researchPrompting(ctx, caseData)
}

func (r *Researcher) researchNative(ctx context.Context, caseData *domain.AnalysisCase, client NativeToolCompleter) (domain.CVEAnalysisProposal, error) {
	proposal := domain.CVEAnalysisProposal{
		ID:         fmt.Sprintf("PROP-%s", caseData.Vulnerability.ID),
		Confidence: "LOW",
	}

	systemPrompt := `You are a Go static analysis assistant analyzing bug root causes and patch diffs.
Your goal is to distinguish the true faulting defect site (where the crash, panic, or vulnerability actually executes) from auxiliary dispatchers and upstream validation guards (where early rejections were added in the patch).
When you have collected enough evidence, output your final proposal in JSON format:
{"id":"...","mechanisms":[{"id":"M-1","summary":"...","faulting_sites":["..."],"auxiliary_sites":["..."],"patch_explanation":"..."}],"confidence":"HIGH"}`

	messages := []ChatMessage{
		{
			Role: "user",
			Content: fmt.Sprintf("Defect %s: %s\nAffected symbols: %v",
				caseData.Vulnerability.ID, caseData.Vulnerability.Summary, caseData.Vulnerability.AffectedSymbols),
		},
	}

	for iter := 1; iter <= r.maxIter; iter++ {
		if llmBudgetExhausted(caseData) {
			return proposal, fmt.Errorf("MaxLLMCalls limit reached")
		}
		caseData.IncLLMCalls()

		respMsg, finish, err := client.Chat(ctx, Analyze, systemPrompt, messages, researchToolDefinitions)
		if err != nil {
			return proposal, err
		}
		if IsRefusal(respMsg.Content, finish) {
			return proposal, fmt.Errorf("llm refusal: %s", DescribeBadOutput(respMsg.Content, finish))
		}

		messages = append(messages, respMsg)

		if len(respMsg.ToolCalls) > 0 {
			if r.tools == nil {
				return proposal, fmt.Errorf("tools runner unavailable")
			}
			for _, tc := range respMsg.ToolCalls {
				caseData.IncToolCalls()
				res := r.tools.Call(ctx, caseData, tc.Function.Name, json.RawMessage(tc.Function.Arguments))
				content := string(res.Content)
				if !res.OK && res.Error != "" {
					content = fmt.Sprintf("error: %s", res.Error)
				}
				messages = append(messages, ChatMessage{
					Role:       "tool",
					ToolCallID: tc.ID,
					Content:    content,
				})
			}
			continue
		}

		clean := ExtractJSON(respMsg.Content)
		if clean != "" {
			var prop domain.CVEAnalysisProposal
			if err := json.Unmarshal([]byte(clean), &prop); err == nil && len(prop.Mechanisms) > 0 {
				prop.ToolIterations = iter
				return prop, nil
			}
			var wrapped struct {
				Proposal *domain.CVEAnalysisProposal `json:"proposal"`
			}
			if err := json.Unmarshal([]byte(clean), &wrapped); err == nil && wrapped.Proposal != nil && len(wrapped.Proposal.Mechanisms) > 0 {
				wrapped.Proposal.ToolIterations = iter
				return *wrapped.Proposal, nil
			}
		}

		messages = append(messages, ChatMessage{
			Role:    "user",
			Content: "Please output the final CVEAnalysisProposal JSON object with id, mechanisms (faulting_sites, auxiliary_sites, patch_explanation), and confidence.",
		})
	}

	return proposal, fmt.Errorf("research loop completed without final proposal")
}

func (r *Researcher) researchPrompting(ctx context.Context, caseData *domain.AnalysisCase) (domain.CVEAnalysisProposal, error) {
	proposal := domain.CVEAnalysisProposal{
		ID:         fmt.Sprintf("PROP-%s", caseData.Vulnerability.ID),
		Confidence: "LOW",
	}

	systemPrompt := `You are a Go static analysis assistant analyzing bug root causes and patch diffs.
Your goal is to distinguish the true faulting defect site from auxiliary dispatchers/guards.

Available tools:
- "read_patch_diff": {} -> returns the patch diff for this defect.
- "inspect_source_file": {"path": "relative/file.go", "start_line": 1, "end_line": 100} -> returns lines from dependency source.
- "analyze_product_scope": {"symbol": "pkg.FuncName"} -> checks if symbol is called in the product.

Respond with strict JSON only:
{"action":"tool","tool":"<tool_name>","args":{...}} OR
{"action":"final","proposal":{"id":"...","mechanisms":[{"id":"M-1","summary":"...","faulting_sites":["..."],"auxiliary_sites":["..."],"patch_explanation":"..."}],"confidence":"HIGH"}}`

	userContent := fmt.Sprintf("Defect %s: %s\nAffected symbols: %v",
		caseData.Vulnerability.ID, caseData.Vulnerability.Summary, caseData.Vulnerability.AffectedSymbols)

	for iter := 1; iter <= r.maxIter; iter++ {
		if llmBudgetExhausted(caseData) {
			return proposal, fmt.Errorf("MaxLLMCalls limit reached")
		}
		caseData.IncLLMCalls()

		resp, finish, err := r.client.Complete(ctx, Analyze, systemPrompt, userContent)
		if err != nil {
			return proposal, err
		}
		if IsRefusal(resp, finish) {
			return proposal, fmt.Errorf("llm refusal: %s", DescribeBadOutput(resp, finish))
		}

		j := ExtractJSON(resp)
		var step researcherStep
		if j == "" || json.Unmarshal([]byte(j), &step) != nil {
			userContent += fmt.Sprintf("\nInvalid JSON response. Output valid JSON adhering to schema.")
			continue
		}

		if step.Action == "final" && step.Proposal != nil {
			proposal = *step.Proposal
			proposal.ToolIterations = iter
			return proposal, nil
		}

		if step.Action == "tool" && step.Tool != "" {
			if r.tools == nil {
				return proposal, fmt.Errorf("tools runner unavailable")
			}
			caseData.IncToolCalls()
			res := r.tools.Call(ctx, caseData, step.Tool, step.Args)
			userContent += fmt.Sprintf("\nTool %s result: %s (error: %s)", step.Tool, string(res.Content), res.Error)
			continue
		}

		break
	}

	return proposal, fmt.Errorf("research loop completed without final proposal")
}
