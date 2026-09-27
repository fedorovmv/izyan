package states

import (
	"context"
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/evaluator"
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/workflow"
)

// GapAnalysis is the bounded hypothesis loop (spec §18): for every
// unresolved mandatory claim it records a Hypothesis, runs the planned
// tool action to produce the expected evidence, re-evaluates the claim,
// and iterates to a fixpoint. An INCONCLUSIVE verdict then carries an
// auditable record of what was tried — not a bare "unknown".
//
// Bounds: maxGapIterations outer rounds; each tool action counts against
// Workflow.Limits.MaxToolCalls.
type GapAnalysis struct {
	Source     *goanalysis.Index
	Evaluators []evaluator.ConditionEvaluator
	// Planner is the optional LLM-driven hypothesis planner (spec §18):
	// it runs once per still-unknown condition when the deterministic
	// actions for it are exhausted. It only decides where to look next;
	// claim results remain the evaluators' job.
	Planner HypothesisPlanner
	// Fallback is the optional LLM claim evaluator. It runs only after the
	// deterministic hypothesis loop AND the planner are exhausted — an LLM
	// claim must never preempt a provable deterministic verdict (e.g. a
	// guard-falsified FALSE a deep trace would have reached).
	Fallback evaluator.ConditionEvaluator
}

// HypothesisPlanner proposes and executes one hypothesis test for an
// unresolved condition. Returns true when new evidence was produced.
type HypothesisPlanner interface {
	Plan(ctx context.Context, cond domain.Condition, c *domain.AnalysisCase) bool
}

const (
	maxGapIterations = 3
	maxLLMPlanSteps  = 3  // LLM planner steps per condition per run
	deepTraceHops    = 16 // extended caller-climb bound for gap traces
)

func (GapAnalysis) State() domain.WorkflowState { return domain.StateGapAnalysis }

func (h GapAnalysis) Run(ctx context.Context, c *domain.AnalysisCase) (workflow.Transition, error) {
	if h.Source == nil || c.Exploit == nil {
		return h.dispatch(c, "no source index — gap analysis skipped")
	}
	planned := map[string]bool{}
	llmSteps := map[domain.ConditionID]int{}
	for iter := 0; iter < maxGapIterations; iter++ {
		progress := false
		for _, cond := range c.Exploit.MandatoryConditions {
			claim := findClaim(c.Claims, cond.ID)
			if claim == nil || claim.Result != domain.ClaimUnknown {
				continue
			}
			// MaxToolCalls==0 means unlimited (tests and small harnesses
			// don't set a budget).
			if max := c.Workflow.Limits.MaxToolCalls; max > 0 &&
				c.UsageSnapshot().ToolCalls >= max {
				c.EvidenceGraph.AddLimitation(
					"gap analysis stopped: MaxToolCalls budget exhausted")
				return h.dispatch(c, "tool budget exhausted")
			}
			moved := h.plan(ctx, c, cond, planned)
			// The deterministic planner had nothing for this condition —
			// let the LLM planner pick the next check, up to
			// maxLLMPlanSteps per condition. Plan returning false means
			// the model declined or produced nothing actionable — stop.
			if !moved && h.Planner != nil && llmSteps[cond.ID] < maxLLMPlanSteps {
				if max := c.Workflow.Limits.MaxLLMCalls; max > 0 &&
					c.UsageSnapshot().LLMCalls >= max {
					c.EvidenceGraph.AddLimitation(
						"gap analysis: LLM planner skipped, MaxLLMCalls exhausted")
				} else {
					llmSteps[cond.ID]++
					moved = h.Planner.Plan(ctx, cond, c)
				}
			}
			progress = moved || progress
		}
		if !progress {
			break
		}
		h.reevaluate(c)
	}
	// The deterministic loop and planner are exhausted. If no mandatory
	// claim is FALSE yet, the LLM fallback may still resolve the remaining
	// UNKNOWNs — claims it cannot back stay UNKNOWN.
	fallbackRan := false
	if h.Fallback != nil && !hasFalseClaim(c) {
		for _, cond := range c.Exploit.MandatoryConditions {
			cl := findClaim(c.Claims, cond.ID)
			if cl == nil || cl.Result != domain.ClaimUnknown ||
				!h.Fallback.CanEvaluate(cond) {
				continue
			}
			if max := c.Workflow.Limits.MaxLLMCalls; max > 0 &&
				c.UsageSnapshot().LLMCalls >= max {
				c.EvidenceGraph.AddLimitation(
					"gap fallback skipped: MaxLLMCalls budget exhausted")
				break
			}
			fallbackRan = true
			if alt := h.Fallback.Evaluate(cond, c); alt.Result != domain.ClaimUnknown ||
				len(alt.EvidenceIDs) > 0 {
				*cl = alt
			}
		}
	}
	reason := "gap analysis complete"
	if fallbackRan {
		reason += "; LLM claim fallback ran after deterministic actions"
	}
	return h.dispatch(c, reason)
}

func hasFalseClaim(c *domain.AnalysisCase) bool {
	for _, cl := range c.Claims {
		if cl.Result == domain.ClaimFalse {
			return true
		}
	}
	return false
}

// dispatch picks the next state by the same rules EVALUATE_CONDITIONS
// applies when no UNKNOWNs remain.
func (h GapAnalysis) dispatch(c *domain.AnalysisCase, reason string) (workflow.Transition, error) {
	hasFalse := false
	for _, cond := range c.Exploit.MandatoryConditions {
		if cl := findClaim(c.Claims, cond.ID); cl != nil && cl.Result == domain.ClaimFalse {
			hasFalse = true
		}
	}
	if hasFalse {
		return workflow.Transition{Next: domain.StateNegativeCheck, Reason: reason + "; candidate FALSE requires negative verification"}, nil
	}
	if allMandatoryTrue(c) {
		return workflow.Transition{Next: domain.StateReview, Reason: reason + "; all mandatory conditions satisfied"}, nil
	}
	return workflow.Transition{Next: domain.StateEvaluateVerdict, Reason: reason}, nil
}

// plan generates and runs one hypothesis action per unresolved condition,
// once per (condition, action) pair. Returns true when an action produced
// new evidence worth re-evaluating.
func (h GapAnalysis) plan(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition, planned map[string]bool) bool {
	flows := flowsForCond(c, cond.ID)
	switch cond.Kind {
	case domain.ConditionAttackerControl, domain.ConditionInputConstraint:
		if len(flows) == 0 {
			// No call sites were ever traced — maybe the sink is invoked
			// dynamically. ScanDynamic documents the hiding mechanism.
			key := string(cond.ID) + ":dynamic"
			if planned[key] {
				return false
			}
			planned[key] = true
			return h.actDynamicDispatch(ctx, c, cond)
		}
		var progress bool
		for _, f := range flows {
			if f.Origin != domain.OriginUnknown {
				continue
			}
			key := fmt.Sprintf("%s:deepen:%s:%d:arg%d", cond.ID, f.Sink.File, f.Sink.Line, f.Arg)
			if planned[key] {
				continue
			}
			planned[key] = true
			progress = h.actDeepTrace(ctx, c, cond, f) || progress
		}
		return progress
	case domain.ConditionSymbolReachable:
		key := string(cond.ID) + ":hidden-reach"
		if planned[key] {
			return false
		}
		planned[key] = true
		return h.actHiddenReach(ctx, c, cond)
	case domain.ConditionValidation:
		key := string(cond.ID) + ":caller-guard"
		if planned[key] {
			return false
		}
		planned[key] = true
		return h.actCallerGuards(ctx, c, cond)
	}
	return false
}

// actCallerGuards climbs the caller chain of each traced sink site
// (FindValidationsBound). A sink-covering guard is emitted only when
// every expanded caller branch guards the argument — partial coverage
// is recorded as informational evidence and keeps the claim UNKNOWN.
func (h GapAnalysis) actCallerGuards(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition) bool {
	flows := flowsForCond(c, cond.ID)
	if len(flows) == 0 {
		c.AddHypothesis(domain.Hypothesis{
			ConditionID:      cond.ID,
			Statement:        "the sink argument may be validated in a caller frame upstream of the traced site",
			ExpectedEvidence: []domain.EvidenceKind{domain.EvidenceValidation},
			Status:           domain.HypothesisUnresolved,
			Notes:            "no data flows recorded; sink sites unknown",
		})
		return false
	}
	progress := false
	var evIDs []domain.EvidenceID
	var notes []string
	for _, f := range flows {
		arg := f.Arg
		if arg < 0 {
			arg = cond.ArgIndex
		}
		if arg < 0 {
			arg = 0
		}
		c.IncToolCalls()
		vals, evs, err := h.Source.FindValidationsBound(ctx, f.Sink, arg, deepTraceHops)
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("gap caller-guard scan %s:%d: %v", f.Sink.File, f.Sink.Line, err))
			continue
		}
		for _, e := range evs {
			evIDs = append(evIDs, c.EvidenceGraph.AddEvidence(e))
		}
		covered := false
		for _, v := range vals {
			if v.Covers != nil {
				covered = true
			}
			c.EvidenceGraph.AddValidations(v)
		}
		if len(vals) > 0 {
			progress = true
			if covered {
				notes = append(notes, fmt.Sprintf("%s:%d fully guarded in caller frames", f.Sink.File, f.Sink.Line))
			} else {
				notes = append(notes, fmt.Sprintf("%s:%d partially guarded in caller frames", f.Sink.File, f.Sink.Line))
			}
		}
	}
	hyp := domain.Hypothesis{
		ConditionID:      cond.ID,
		Statement:        "the sink argument may be validated in a caller frame upstream of the traced site",
		ExpectedEvidence: []domain.EvidenceKind{domain.EvidenceValidation},
		EvidenceIDs:      evIDs,
		Status:           domain.HypothesisRejected,
		Notes:            "no caller-frame guards found on any expanded path",
	}
	if len(notes) > 0 {
		hyp.Notes = strings.Join(notes, "; ")
		hyp.Status = domain.HypothesisConfirmed
	}
	c.AddHypothesis(hyp)
	return progress
}

// actDeepTrace re-runs argument provenance with an extended caller-climb
// budget. A resolved origin supersedes the shallow UNKNOWN flow.
func (h GapAnalysis) actDeepTrace(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition, f domain.DataFlow) bool {
	// Trace the argument this flow actually recorded — multi-arg sinks
	// carry f.Arg per flow; falling back to cond.ArgIndex would re-trace
	// arg 0 and leave the unknown arg untouched.
	arg := f.Arg
	if arg < 0 {
		arg = cond.ArgIndex
	}
	if arg < 0 {
		arg = 0
	}
	c.IncToolCalls()
	deeper, evs, err := h.Source.TraceArgumentBound(ctx, f.Sink, arg, deepTraceHops)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("gap deep-trace %s:%d: %v", f.Sink.File, f.Sink.Line, err))
		return false
	}
	var evIDs []domain.EvidenceID
	for _, e := range evs {
		evIDs = append(evIDs, c.EvidenceGraph.AddEvidence(e))
	}
	hyp := domain.Hypothesis{
		ConditionID:      cond.ID,
		Statement:        fmt.Sprintf("origin of arg %d at %s:%d is resolvable deeper in the caller chain", arg, f.Sink.File, f.Sink.Line),
		ExpectedEvidence: []domain.EvidenceKind{domain.EvidenceDataFlow},
		EvidenceIDs:      evIDs,
		Status:           domain.HypothesisUnresolved,
		Notes:            fmt.Sprintf("deeper trace (%d hops) still could not resolve the origin", deepTraceHops),
	}
	if deeper.Origin != domain.OriginUnknown && deeper.Origin != "" {
		deeper.ConditionID = cond.ID
		c.EvidenceGraph.ReplaceDataFlow(deeper)
		hyp.Status = domain.HypothesisConfirmed
		hyp.Notes = fmt.Sprintf("deeper trace resolved origin to %s: %s", deeper.Origin, deeper.Summary)
		c.AddHypothesis(hyp)
		return true
	}
	c.AddHypothesis(hyp)
	return false
}

// actDynamicDispatch documents whether the sink could be invoked through
// mechanisms static call-site scans miss. Markers found mean the UNKNOWN
// is honest coverage loss — the claim must not become FALSE.
func (h GapAnalysis) actDynamicDispatch(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition) bool {
	if cond.Subject == nil {
		return false
	}
	c.IncToolCalls()
	markers, err := h.Source.ScanDynamic(ctx, *cond.Subject)
	if err != nil {
		c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("gap dynamic scan: %v", err))
		return false
	}
	var evIDs []domain.EvidenceID
	if len(markers) > 0 {
		var detail string
		for i, m := range markers {
			if i > 0 {
				detail += "; "
			}
			detail += fmt.Sprintf("%s %s:%d %s", m.Kind, m.File, m.Line, m.Detail)
		}
		evIDs = append(evIDs, c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSearchResult,
			Quality: domain.QualityDeterministic,
			Source:  "gap analysis: dynamic dispatch scan",
			Tool:    "goanalysis.Index.ScanDynamic",
			Content: detail,
		}))
	}
	hyp := domain.Hypothesis{
		ConditionID:      cond.ID,
		Statement:        "the sink may be invoked through dynamic dispatch invisible to static call-site scans",
		ExpectedEvidence: []domain.EvidenceKind{domain.EvidenceSearchResult},
		EvidenceIDs:      evIDs,
	}
	if len(markers) > 0 {
		hyp.Status = domain.HypothesisConfirmed
		hyp.Notes = fmt.Sprintf("%d dynamic marker(s) — coverage loss is documented, claim stays UNKNOWN", len(markers))
	} else {
		hyp.Status = domain.HypothesisRejected
		hyp.Notes = "no dynamic-dispatch markers near the subject"
	}
	c.AddHypothesis(hyp)
	return false // documents scope loss; does not move the claim
}

// actHiddenReach checks for a plausible path the static scan cannot
// prove: interface-dispatch call sites and build-tag-excluded references.
func (h GapAnalysis) actHiddenReach(ctx context.Context, c *domain.AnalysisCase, cond domain.Condition) bool {
	if cond.Subject == nil {
		return false
	}
	c.IncToolCalls()
	var sites []domain.CallSite
	if s, err := h.Source.InterfaceDispatchSites(ctx, *cond.Subject); err == nil {
		sites = append(sites, s...)
	}
	if s, err := h.Source.GatedRefs(ctx, *cond.Subject); err == nil {
		sites = append(sites, s...)
	}
	var evIDs []domain.EvidenceID
	if len(sites) > 0 {
		var detail string
		for i, s := range sites {
			if i > 0 {
				detail += "; "
			}
			detail += fmt.Sprintf("%s:%d %s", s.File, s.Line, s.Function)
		}
		evIDs = append(evIDs, c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSearchResult,
			Quality: domain.QualityDeterministic,
			Source:  "gap analysis: hidden reachability",
			Tool:    "goanalysis.Index.InterfaceDispatchSites+GatedRefs",
			Content: detail,
		}))
	}
	hyp := domain.Hypothesis{
		ConditionID:      cond.ID,
		Statement:        "the subject may be reachable through interface dispatch or build-tagged files invisible to the typed index",
		ExpectedEvidence: []domain.EvidenceKind{domain.EvidenceSearchResult},
		EvidenceIDs:      evIDs,
	}
	if len(sites) > 0 {
		hyp.Status = domain.HypothesisConfirmed
		hyp.Notes = fmt.Sprintf("%d plausible site(s) outside the typed scope", len(sites))
	} else {
		hyp.Status = domain.HypothesisRejected
		hyp.Notes = "no interface-dispatch or build-gated reference sites"
	}
	c.AddHypothesis(hyp)
	return false
}

// reevaluate re-runs deterministic evaluators on still-UNKNOWN claims —
// new flows from this round may have resolved them.
func (h GapAnalysis) reevaluate(c *domain.AnalysisCase) {
	if c.Exploit == nil {
		return
	}
	for _, cond := range c.Exploit.MandatoryConditions {
		cl := findClaim(c.Claims, cond.ID)
		if cl == nil || cl.Result != domain.ClaimUnknown {
			continue
		}
		for _, ev := range h.Evaluators {
			if !ev.CanEvaluate(cond) {
				continue
			}
			next := ev.Evaluate(cond, c)
			if next.Result != domain.ClaimUnknown || len(next.EvidenceIDs) > 0 {
				*cl = next
			}
			break
		}
	}
}

func flowsForCond(c *domain.AnalysisCase, id domain.ConditionID) []domain.DataFlow {
	var out []domain.DataFlow
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID == id {
			out = append(out, f)
		}
	}
	return out
}
