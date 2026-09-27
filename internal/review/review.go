// Package review implements the deterministic structural reviewer. It
// audits the immutable evidence/claim package before the verdict is
// finalized: unsupported TRUE/FALSE claims, dangling evidence references,
// contradictions and scope mismatches become findings. REVISE findings
// with severity=high are repaired by demoting the claim to UNKNOWN —
// the reviewer never sets the verdict itself.
package review

import (
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/exploit"
	"path/filepath"
)

// Reviewer audits a case against its proposed verdict.
type Reviewer interface {
	Review(c *domain.AnalysisCase, proposed domain.VerdictResult) domain.Review
}

// Multi runs several reviewers and merges their findings. REVISE wins
// over ACCEPT; finding lists are concatenated.
type Multi []Reviewer

func (m Multi) Review(c *domain.AnalysisCase, proposed domain.VerdictResult) domain.Review {
	out := domain.Review{Result: domain.ReviewAccept}
	for _, r := range m {
		if r == nil {
			continue
		}
		sub := r.Review(c, proposed)
		out.Findings = append(out.Findings, sub.Findings...)
		if sub.Result == domain.ReviewRevise {
			out.Result = domain.ReviewRevise
		}
	}
	return out
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
			// A VERIFIED negative check that still records dynamic-dispatch
			// caveats (reflect/unsafe/plugin) does not support FALSE on this
			// codebase — demote deterministically instead of relying on the
			// LLM reviewer to notice.
			if nv == nil {
				break
			}
			for _, l := range nv.Limitations {
				if strings.Contains(l, "widens the call graph") {
					findings = append(findings, domain.ReviewFinding{
						TargetType: "claim", TargetID: string(cl.ID), Severity: "high",
						Problem: "FALSE claim verified but dynamic dispatch markers limit coverage: " + l,
					})
					break
				}
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

	// Class-pattern coverage: a class-matched model must instantiate every
	// mandatory template of its pattern. A missing condition may be a
	// legitimate bind skip (recorded in graph limitations) or a dropped
	// check in a hand/LLM-built model — medium severity, never blocking.
	if c.Exploit != nil && c.Exploit.Class != "" {
		if pat := exploit.Lookup(exploit.Class(c.Exploit.Class)); pat != nil {
			present := map[string]bool{}
			for _, cond := range c.Exploit.MandatoryConditions {
				present[string(cond.ID)] = true
			}
			for _, t := range pat.Mandatory {
				if present[t.ID] {
					continue
				}
				var skipped bool
				for _, l := range c.EvidenceGraph.Limitations {
					if strings.Contains(l, t.ID) || strings.Contains(l, t.Description) {
						skipped = true
						break
					}
				}
				sev := "medium"
				if !skipped {
					sev = "high" // absent and not a recorded bind skip — likely dropped
				}
				findings = append(findings, domain.ReviewFinding{
					TargetType: "model", TargetID: t.ID, Severity: sev,
					Problem: fmt.Sprintf("class %s pattern expects mandatory %s; model lacks it (skipped=%v)",
						c.Exploit.Class, t.ID, skipped),
				})
			}
		}
	}

	// Patch misinterpretation: when fix-diff evidence exists, at least one
	// resolved root-cause symbol should appear in it — the root cause may
	// legitimately come from advisory symbols instead, so this is a
	// medium-severity signal, not a verdict blocker.
	if c.RootCause != nil && len(c.RootCause.RootCauses) > 0 {
		var diffs []string
		for _, e := range c.EvidenceGraph.Evidence {
			if e.Kind == domain.EvidenceFixDiff {
				diffs = append(diffs, e.Content)
			}
		}
		if len(diffs) > 0 {
			joined := strings.Join(diffs, "\n")
			var named []string
			for _, rc := range c.RootCause.RootCauses {
				base := rc.Symbol
				if i := strings.LastIndex(base, "."); i >= 0 {
					base = base[i+1:]
				}
				if strings.Contains(joined, base) {
					named = append(named, rc.Symbol)
				}
			}
			if len(named) == 0 {
				findings = append(findings, domain.ReviewFinding{
					TargetType: "model", Severity: "medium",
					Problem: "no root-cause symbol appears in any fix diff — possible patch misinterpretation or advisory-derived root cause",
				})
			}
		}
	}

	// Scope mismatch: evidence files must live under the analyzed product
	// tree or a Go module cache — anywhere else means a source/tool
	// produced evidence outside the declared scope.
	if c.Product.Repository != "" {
		repo := filepath.Clean(c.Product.Repository) + string(filepath.Separator)
		for _, e := range c.EvidenceGraph.Evidence {
			f := e.File
			if f == "" || !filepath.IsAbs(f) || !strings.HasSuffix(f, ".go") {
				continue // only source files carry a meaningful scope
			}
			if strings.HasPrefix(filepath.Clean(f), repo) || strings.Contains(f, "/pkg/mod/") {
				continue
			}
			findings = append(findings, domain.ReviewFinding{
				TargetType: "claim", TargetID: string(e.ID), Severity: "medium",
				Problem: fmt.Sprintf("evidence %s references file outside analyzed scope: %s", e.ID, f),
			})
		}
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
