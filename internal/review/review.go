// Package review implements the deterministic structural reviewer. It
// audits the immutable evidence/claim package before the verdict is
// finalized: unsupported TRUE/FALSE claims, dangling evidence references,
// contradictions and scope mismatches become findings. REVISE findings
// with severity=high are repaired by demoting the claim to UNKNOWN —
// the reviewer never sets the verdict itself.
package review

import (
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// Reviewer audits a case against its proposed verdict.
type Reviewer interface {
	Review(c *domain.AnalysisCase, proposed domain.VerdictResult) domain.Review
}

// Structural is the deterministic reviewer — no LLM.
type Structural struct{}

func (Structural) Review(c *domain.AnalysisCase, proposed domain.VerdictResult) domain.Review {
	r := domain.Review{ID: domain.ReviewID(fmt.Sprintf("REV-%d", len(c.Reviews)+1)), Result: domain.ReviewAccept}
	var findings []domain.ReviewFinding

	evIDs := map[domain.EvidenceID]bool{}
	for _, e := range c.EvidenceGraph.Evidence {
		evIDs[e.ID] = true
	}

	mandatory := map[domain.ConditionID]bool{}
	if c.Exploit != nil {
		for _, cond := range c.Exploit.MandatoryConditions {
			mandatory[cond.ID] = true
		}
	}

	for i := range c.Claims {
		cl := c.Claims[i]
		for _, id := range cl.EvidenceIDs {
			if !evIDs[id] {
				findings = append(findings, domain.ReviewFinding{
					TargetType: "claim", TargetID: string(cl.ID), Severity: "high",
					Problem: fmt.Sprintf("claim %s cites missing evidence %s", cl.ConditionID, id),
				})
			}
		}
		switch cl.Result {
		case domain.ClaimTrue:
			if len(cl.EvidenceIDs) == 0 {
				findings = append(findings, domain.ReviewFinding{
					TargetType: "claim", TargetID: string(cl.ID), Severity: "high",
					Problem:       "TRUE claim carries no evidence",
					RequiredCheck: "attach deterministic evidence or demote to UNKNOWN",
				})
			}
		case domain.ClaimFalse:
			nv := cl.NegativeVerification
			switch {
			case nv == nil:
				findings = append(findings, domain.ReviewFinding{
					TargetType: "claim", TargetID: string(cl.ID), Severity: "high",
					Problem: "FALSE claim never passed negative verification",
				})
			case nv.Status == domain.NegativeContradicted:
				findings = append(findings, domain.ReviewFinding{
					TargetType: "claim", TargetID: string(cl.ID), Severity: "high",
					Problem: "FALSE claim contradicted but not demoted",
				})
			case nv.Status == domain.NegativeInsufficientScope:
				findings = append(findings, domain.ReviewFinding{
					TargetType: "claim", TargetID: string(cl.ID), Severity: "medium",
					Problem: "FALSE claim lacks verified negative check; verdict cannot rely on it",
				})
			}
		}
		if cl.Result == domain.ClaimUnknown && mandatory[cl.ConditionID] {
			findings = append(findings, domain.ReviewFinding{
				TargetType: "claim", TargetID: string(cl.ID), Severity: "low",
				Problem: "mandatory condition unresolved",
			})
		}
	}

	if c.Exploit != nil && len(c.Exploit.MandatoryConditions) > 0 && c.RootCause == nil {
		findings = append(findings, domain.ReviewFinding{
			TargetType: "model", Severity: "high",
			Problem: "exploit model exists without a resolved root cause",
		})
	}

	if (proposed.Verdict == domain.VerdictExploitable || proposed.Verdict == domain.VerdictNoExploitPathFound) &&
		len(c.EvidenceGraph.ToolLimitations) > 0 {
		findings = append(findings, domain.ReviewFinding{
			TargetType: "verdict", Severity: "medium",
			Problem: fmt.Sprintf("verdict %s reached while %d tool limitation(s) are recorded",
				proposed.Verdict, len(c.EvidenceGraph.ToolLimitations)),
		})
	}

	r.Findings = findings
	for _, f := range findings {
		if f.Severity == "high" {
			r.Result = domain.ReviewRevise
			break
		}
	}
	return r
}
