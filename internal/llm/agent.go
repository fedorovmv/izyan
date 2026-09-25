package llm

import (
	"context"
	"encoding/json"
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// ClaimEvaluator resolves UNKNOWN conditions through a bounded tool loop:
// the analyze model requests deterministic tools, their outputs land in the
// evidence graph, and a claim proposal is accepted only if every cited
// evidence id exists in the graph. FALSE proposals still pass through the
// negative verifier downstream — the model cannot assert safety by prose.
type ClaimEvaluator struct {
	Client   *Client
	Tools    Tools
	MaxSteps int // default 8
}

// agentStep is one model response: either tool calls or a claim proposal.
type agentStep struct {
	ToolCalls []struct {
		Name    string          `json:"name"`
		Args    json.RawMessage `json:"args"`
		Purpose string          `json:"purpose"`
	} `json:"tool_calls"`
	Claim *struct {
		Result      string   `json:"result"`
		EvidenceIDs []string `json:"evidence_ids"`
		Explanation string   `json:"explanation"`
	} `json:"claim"`
}

func (ClaimEvaluator) CanEvaluate(cond domain.Condition) bool {
	// The agent may attack anything except SYMBOL_REACHABLE — that one is
	// decided by govulncheck alone.
	return cond.Kind != domain.ConditionSymbolReachable
}

func (a ClaimEvaluator) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
	}
	if a.Client == nil || a.Tools.Source == nil || llmBudgetExhausted(c) {
		claim.Limitations = append(claim.Limitations, "agent evaluator unavailable or budget exhausted")
		return claim
	}
	if err := a.Tools.Source.Loaded(context.Background()); err != nil {
		claim.Limitations = append(claim.Limitations, "source index unavailable: "+err.Error())
		return claim
	}

	steps := a.MaxSteps
	if steps <= 0 {
		steps = 8
	}
	ctx := withCond(context.Background(), cond.ID)
	var transcript []chatMessage
	system := agentSystem + a.Tools.Schemas()
	user := agentUser(cond, c)
	transcript = append(transcript, chatMessage{Role: "user", Content: user})

	for step := 0; step < steps; step++ {
		if llmBudgetExhausted(c) {
			claim.Limitations = append(claim.Limitations, "llm call budget exhausted mid-loop")
			return claim
		}
		c.IncLLMCalls()
		out, err := a.Client.CompleteMessages(ctx, Analyze, system, transcript)
		if err != nil {
			claim.Limitations = append(claim.Limitations, "agent step failed: "+err.Error())
			return claim
		}
		var st agentStep
		j := ExtractJSON(out)
		if j == "" || json.Unmarshal([]byte(j), &st) != nil {
			transcript = append(transcript,
				chatMessage{Role: "assistant", Content: out},
				chatMessage{Role: "user", Content: "Response not valid JSON. Reply only with the documented schema."})
			continue
		}
		if st.Claim != nil {
			return a.acceptClaim(claim, *st.Claim, c)
		}
		if len(st.ToolCalls) == 0 {
			transcript = append(transcript,
				chatMessage{Role: "assistant", Content: out},
				chatMessage{Role: "user", Content: "Specify tool_calls or claim."})
			continue
		}
		results := make([]map[string]any, 0, len(st.ToolCalls))
		for i, tc := range st.ToolCalls {
			if i >= 4 {
				break
			}
			tr := a.Tools.Call(ctx, c, tc.Name, tc.Args)
			results = append(results, map[string]any{
				"tool": tc.Name, "purpose": tc.Purpose,
				"evidence_id": tr.EvidenceID, "ok": tr.OK,
				"content": json.RawMessage(tr.Content), "error": tr.Error,
			})
		}
		b, _ := json.Marshal(map[string]any{"tool_results": results})
		transcript = append(transcript,
			chatMessage{Role: "assistant", Content: out},
			chatMessage{Role: "user", Content: string(b)})
	}
	claim.Limitations = append(claim.Limitations,
		fmt.Sprintf("agent loop reached %d steps without a claim", steps))
	return claim
}

// acceptClaim validates the proposal: TRUE requires at least one graph
// evidence id; FALSE/UNKNOWN are recorded but only evidence-backed claims
// keep their evidence links.
func (a ClaimEvaluator) acceptClaim(claim domain.Claim, p struct {
	Result      string   `json:"result"`
	EvidenceIDs []string `json:"evidence_ids"`
	Explanation string   `json:"explanation"`
}, c *domain.AnalysisCase) domain.Claim {
	valid := map[domain.EvidenceID]bool{}
	for _, e := range c.EvidenceGraph.EvidenceList() {
		valid[e.ID] = true
	}
	var ids []domain.EvidenceID
	for _, id := range p.EvidenceIDs {
		if valid[domain.EvidenceID(id)] {
			ids = append(ids, domain.EvidenceID(id))
		}
	}
	claim.Explanation = p.Explanation
	switch domain.ClaimResult(p.Result) {
	case domain.ClaimTrue:
		if len(ids) == 0 {
			claim.Limitations = append(claim.Limitations,
				"llm proposed TRUE without citing collected evidence; kept UNKNOWN")
			return claim
		}
		claim.Result = domain.ClaimTrue
		claim.EvidenceIDs = ids
	case domain.ClaimFalse:
		claim.Result = domain.ClaimFalse
		claim.EvidenceIDs = ids
		claim.Limitations = append(claim.Limitations,
			"FALSE proposed by agent; pending negative verification")
	default:
		claim.Result = domain.ClaimUnknown
		claim.EvidenceIDs = ids
	}
	return claim
}

const agentSystem = `You are a security claim analyst inside a bounded tool loop.
Goal: resolve ONE condition to TRUE, FALSE or UNKNOWN using evidence.

Rules:
- Every response is a single JSON object. No prose.
- To gather facts: {"tool_calls":[{"name":"<tool>","args":{...},"purpose":"..."}]}
- To conclude: {"claim":{"result":"TRUE|FALSE|UNKNOWN","evidence_ids":["EV-..."],"explanation":"..."}}
- TRUE requires evidence_ids collected via tools in this loop.
- FALSE is strong: only propose it when tool coverage is complete (all call
  sites inspected, no dynamic dispatch). It will be independently falsified.
- Prefer UNKNOWN over guessing. Never invent evidence ids.
- Minimal targeted calls only; each call must serve the condition.

Tools:
`

// agentUser builds the working context for one condition — no global
// transcript, per spec §20: current condition, sinks, existing claims and
// evidence summaries only.
func agentUser(cond domain.Condition, c *domain.AnalysisCase) string {
	var claims []map[string]any
	for _, cl := range c.Claims {
		claims = append(claims, map[string]any{
			"condition": cl.ConditionID, "result": cl.Result,
			"evidence": len(cl.EvidenceIDs),
		})
	}
	var evs []map[string]any
	for _, e := range c.EvidenceGraph.EvidenceList() {
		evs = append(evs, map[string]any{
			"id": e.ID, "kind": e.Kind, "source": e.Source,
		})
	}
	var subjects []map[string]string
	for _, s := range cond.Subjects {
		subjects = append(subjects, map[string]string{"package": s.Package, "symbol": s.Symbol})
	}
	if cond.Subject != nil {
		subjects = append(subjects, map[string]string{"package": cond.Subject.Package, "symbol": cond.Subject.Symbol})
	}
	payload, _ := json.MarshalIndent(map[string]any{
		"vulnerability": map[string]string{"id": c.Vulnerability.ID, "summary": c.Vulnerability.Summary},
		"condition": map[string]any{
			"id": cond.ID, "kind": cond.Kind, "description": cond.Description,
			"subjects": subjects, "arg_index": cond.ArgIndex,
		},
		"existing_claims": claims,
		"evidence":        evs,
	}, "", "  ")
	return "Resolve this condition. Working context:\n" + string(payload)
}
