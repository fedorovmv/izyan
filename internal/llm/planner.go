package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"

	"example.com/vuln-analyzer/internal/domain"
)

// Planner is the LLM-driven hypothesis planner for GAP_ANALYSIS: for one
// UNKNOWN condition it asks the model for a falsifiable hypothesis and ONE
// tool call to test it. The call executes through the typed tool layer
// (budgets, evidence registration), the hypothesis is persisted on the
// case, and claim re-evaluation stays deterministic — the model proposes
// where to look, never what the claim means.
//
// Multi-step: GAP_ANALYSIS may call Plan again on the next iteration for
// the same condition, up to its per-condition step cap — a tool miss is a
// REJECTED hypothesis and worth retrying with a different tool, while
// UNRESOLVED (model declined / unparseable / malformed) ends planning.
type Planner struct {
	Client *Client
	Tools  Tools
}

// planStep is one planner response: a falsifiable hypothesis plus the
// single tool call intended to test it. tool_call may be null when the
// model sees no useful action — that is recorded as UNRESOLVED rather
// than retried.
type planStep struct {
	Hypothesis struct {
		Statement        string   `json:"statement"`
		ExpectedEvidence []string `json:"expected_evidence"`
	} `json:"hypothesis"`
	ToolCall *struct {
		Name    string          `json:"name"`
		Args    json.RawMessage `json:"args"`
		Purpose string          `json:"purpose"`
	} `json:"tool_call"`
}

var toolName = regexp.MustCompile(`^[a-z_]+$`)

// Plan runs one planner step for an unresolved condition. Returns true
// when a tool call was actually attempted — confirmed or rejected — so the
// caller may plan another step; false when the model produced nothing
// actionable (declined, unparseable, malformed name) and should not be
// asked again for this condition.
func (p Planner) Plan(ctx context.Context, cond domain.Condition, c *domain.AnalysisCase) bool {
	if p.Client == nil || p.Tools.Source == nil || llmBudgetExhausted(c) {
		return false
	}
	record := func(h domain.Hypothesis) { c.AddHypothesis(h) }
	hyp := domain.Hypothesis{
		ConditionID: cond.ID,
		Status:      domain.HypothesisOpen,
	}

	c.IncLLMCalls()
	out, finish, err := p.Client.CompleteMessages(ctx, Analyze, planSystem+p.Tools.Schemas(),
		[]chatMessage{{Role: "user", Content: planUser(cond, c)}})
	if err != nil {
		hyp.Status = domain.HypothesisUnresolved
		hyp.Notes = "llm planner call failed: " + err.Error()
		record(hyp)
		return false
	}
	var st planStep
	j := ExtractJSON(out)
	if j == "" || json.Unmarshal([]byte(j), &st) != nil {
		hyp.Status = domain.HypothesisUnresolved
		hyp.Notes = "llm planner returned unusable output: " + DescribeBadOutput(out, finish)
		record(hyp)
		return false
	}
	if st.Hypothesis.Statement == "" {
		st.Hypothesis.Statement = "(unnamed hypothesis)"
	}
	hyp.Statement = st.Hypothesis.Statement
	for _, k := range st.Hypothesis.ExpectedEvidence {
		hyp.ExpectedEvidence = append(hyp.ExpectedEvidence, domain.EvidenceKind(k))
	}
	if st.ToolCall == nil {
		hyp.Status = domain.HypothesisUnresolved
		hyp.Notes = "planner sees no useful tool action for this condition"
		record(hyp)
		return false
	}
	if !toolName.MatchString(st.ToolCall.Name) {
		hyp.Status = domain.HypothesisUnresolved
		hyp.Notes = "planner proposed malformed tool name: " + st.ToolCall.Name
		record(hyp)
		return false
	}

	tr := p.Tools.Call(withCond(ctx, cond.ID), c, st.ToolCall.Name, st.ToolCall.Args)
	if tr.EvidenceID != "" {
		hyp.EvidenceIDs = append(hyp.EvidenceIDs, tr.EvidenceID)
	}
	if tr.Error != "" || !tr.OK {
		hyp.Status = domain.HypothesisRejected
		hyp.Notes = fmt.Sprintf("tool %s: %s", st.ToolCall.Name, tr.Error)
		record(hyp)
		return true // a miss is knowledge — the next step may pick another tool
	}
	hyp.Status = domain.HypothesisConfirmed
	hyp.Notes = fmt.Sprintf("tool %s (%s) produced %s", st.ToolCall.Name, st.ToolCall.Purpose, tr.EvidenceID)
	record(hyp)
	return true
}

const planSystem = `You are the hypothesis planner inside a bounded vulnerability
analysis loop. For the given UNKNOWN condition, propose ONE falsifiable
hypothesis and ONE tool call to test it.

Rules:
- Reply with a single JSON object, no prose:
  {"hypothesis":{"statement":"...","expected_evidence":["EVIDENCE_KIND",...]},
   "tool_call":{"name":"<tool>","args":{...},"purpose":"..."}}
- expected_evidence uses kind names: SOURCE_SNIPPET, CALL_PATH, DATA_FLOW,
  VALIDATION, SEARCH_RESULT, MODULE_GRAPH, GOVULNCHECK, ADVISORY, FIX_DIFF,
  CONFIGURATION, BUILD, TEST.
- The hypothesis must state what the tool call could prove or disprove.
- Prefer tools that add evidence the loop has not seen; do not re-run a
  check whose result is already in the evidence list.
- You may be asked again for a follow-up step: build on prior hypotheses
  instead of repeating a REJECTED tool call.
- If no useful action exists, return "tool_call": null.
- You never assert claim results — deterministic evaluation does that.

Tools:
`

// planUser builds the planner context: the unresolved condition plus
// already-recorded hypotheses so the model does not re-propose them.
func planUser(cond domain.Condition, c *domain.AnalysisCase) string {
	subjects := make([]map[string]string, 0, len(cond.Subjects)+1)
	for _, s := range cond.Subjects {
		subjects = append(subjects, map[string]string{"package": s.Package, "symbol": s.Symbol})
	}
	if cond.Subject != nil {
		subjects = append(subjects, map[string]string{"package": cond.Subject.Package, "symbol": cond.Subject.Symbol})
	}
	var hyps []map[string]any
	for _, h := range c.Hypotheses {
		if h.ConditionID == cond.ID {
			hyps = append(hyps, map[string]any{
				"statement": h.Statement, "status": h.Status, "notes": h.Notes,
			})
		}
	}
	var evs []map[string]any
	for _, e := range c.EvidenceGraph.EvidenceList() {
		evs = append(evs, map[string]any{
			"id": e.ID, "kind": e.Kind, "source": e.Source,
		})
	}
	payload, _ := json.MarshalIndent(map[string]any{
		"vulnerability": map[string]string{"id": c.Vulnerability.ID, "summary": c.Vulnerability.Summary},
		"condition": map[string]any{
			"id": cond.ID, "kind": cond.Kind, "description": cond.Description,
			"subjects": subjects, "arg_index": cond.ArgIndex,
		},
		"prior_hypotheses": hyps,
		"evidence":         evs,
	}, "", "  ")
	return "Plan one hypothesis for this unresolved condition:\n" + string(payload)
}
