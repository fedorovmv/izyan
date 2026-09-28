package llm

import (
	"context"
	"encoding/json"

	"example.com/vuln-analyzer/internal/domain"
)

// Reviewer asks the analyze model to audit the proposed-verdict package.
// It complements the structural reviewer: findings are advisory — they
// trigger the same bounded repair (claim demotion), never a stronger claim.
type Reviewer struct {
	Client *Client
}

const reviewSystem = `You are a security review auditor. Given a vulnerability
analysis package (root cause, exploit conditions, claims, limitations,
proposed verdict), find problems the pipeline missed: unsupported claims,
missed mandatory conditions, scope mismatch, dynamic behavior, contradicted
evidence, wrong patch interpretation.
Claim semantics — read before judging "contradictions":
- A FALSE claim on a mandatory exploit condition means "the product's inputs
  or paths provably cannot satisfy this condition" — a legitimate safe
  outcome (verdict NO_EXPLOIT_PATH_FOUND), NOT a claim that the advisory or
  root cause is wrong. The advisory describes the dependency's flaw; claims
  describe whether this product snapshot can trigger it. A FALSE claim does
  not "contradict the root cause mechanism" just because the condition text
  restates the mechanism.
- negative_verification VERIFIED on a FALSE claim means the falsifier was
  re-checked against dynamic-dispatch and coverage markers. If the claim was
  later demoted to UNKNOWN by a review, the VERIFIED tag stays as history —
  that pairing is expected, not an internal contradiction.
- Demote a FALSE claim only when you can point to a concrete artifact: an
  uncovered write site, a traced external origin, a dynamic-dispatch marker,
  or a missing condition — not because its conclusion feels incompatible
  with the advisory.
Output JSON: {"result":"ACCEPT"|"REVISE","findings":[{"target_type":"claim|condition|model|verdict","target_id":"...","problem":"...","severity":"low|medium|high","required_check":"..."}]}
Never propose a different verdict. Only flag gaps a human would check.`

func (rv Reviewer) Review(c *domain.AnalysisCase, proposed domain.VerdictResult) domain.Review {
	r := domain.Review{Result: domain.ReviewAccept}
	if rv.Client == nil || llmBudgetExhausted(c) {
		return r
	}
	payload := reviewPayload(c, proposed)
	user, _ := json.Marshal(payload)
	c.IncLLMCalls()
	out, err := rv.Client.Complete(context.Background(), Analyze, reviewSystem, string(user))
	if err != nil {
		r.Findings = append(r.Findings, domain.ReviewFinding{
			TargetType: "verdict", Severity: "low",
			Problem: "llm review unavailable: " + err.Error(),
		})
		return r
	}
	var resp struct {
		Result   string                 `json:"result"`
		Findings []domain.ReviewFinding `json:"findings"`
	}
	if j := ExtractJSON(out); j == "" || json.Unmarshal([]byte(j), &resp) != nil {
		r.Findings = append(r.Findings, domain.ReviewFinding{
			TargetType: "verdict", Severity: "low",
			Problem: "llm review response unparseable",
		})
		return r
	}
	if resp.Result == "REVISE" && len(resp.Findings) == 0 {
		resp.Result = "ACCEPT"
	}
	for _, f := range resp.Findings {
		if f.Severity != "high" && f.Severity != "medium" && f.Severity != "low" {
			f.Severity = "low"
		}
		r.Findings = append(r.Findings, f)
	}
	if resp.Result == "REVISE" {
		r.Result = domain.ReviewRevise
	}
	return r
}

func reviewPayload(c *domain.AnalysisCase, proposed domain.VerdictResult) any {
	claims := make([]map[string]any, 0, len(c.Claims))
	for _, cl := range c.Claims {
		nv := ""
		if cl.NegativeVerification != nil {
			nv = string(cl.NegativeVerification.Status)
		}
		claims = append(claims, map[string]any{
			"id": cl.ID, "condition": cl.ConditionID, "result": cl.Result,
			"evidence": len(cl.EvidenceIDs), "negative_verification": nv,
			"limitations": cl.Limitations,
		})
	}
	var conds []map[string]any
	if c.Exploit != nil {
		for _, cond := range c.Exploit.MandatoryConditions {
			conds = append(conds, map[string]any{
				"id": cond.ID, "kind": cond.Kind, "description": cond.Description,
			})
		}
	}
	var rcs []map[string]any
	if c.RootCause != nil {
		for _, r := range c.RootCause.RootCauses {
			rcs = append(rcs, map[string]any{
				"package": r.Package, "symbol": r.Symbol, "role": r.Role,
				"mechanism": r.Mechanism,
			})
		}
	}
	return map[string]any{
		"vulnerability":        c.Vulnerability.ID,
		"summary":              c.Vulnerability.Summary,
		"root_causes":          rcs,
		"mandatory_conditions": conds,
		"claims":               claims,
		"limitations":          c.EvidenceGraph.Limitations,
		"tool_limitations":     c.EvidenceGraph.ToolLimitations,
		"proposed_verdict":     proposed.Verdict,
		"proposed_reason":      proposed.Reason,
	}
}
