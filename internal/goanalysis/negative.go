package goanalysis

import (
	"context"
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// Verifier performs a bounded negative verification pass on FALSE claims.
// It searches for alternate references, dynamic escapes and provenance
// bypasses that static analysis may have missed. A FALSE claim only survives
// when the falsification pass finds no counterexample within the searchable
// scope; contradictions demote it back to UNKNOWN.
type Verifier struct {
	Source *Index
}

// VerifyFalse attempts to falsify a FALSE claim about subject and returns the
// updated claim with its NegativeVerification result.
func (v Verifier) VerifyFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition, subject domain.SymbolRef) domain.Claim {

	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	if v.Source == nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "source index not configured",
		})
	}

	sites, err := v.Source.SearchSymbol(ctx, subject)
	if err != nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "symbol search failed: " + err.Error(),
		})
	}

	markers, err := v.Source.ScanDynamic(ctx, subject)
	if err != nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "dynamic scan failed: " + err.Error(),
		})
	}
	for _, m := range markers {
		evID := c.EvidenceGraph.AddEvidence(domain.Evidence{
			Kind:    domain.EvidenceSourceSnippet,
			Quality: domain.QualityDeterministic,
			Source:  "go-analysis ScanDynamic",
			Tool:    "goanalysis.Index",
			Content: fmt.Sprintf("%s at %s:%d: %s", m.Kind, m.File, m.Line, m.Detail),
		})
		nv.EvidenceIDs = append(nv.EvidenceIDs, evID)
		switch m.Kind {
		case "func_value", "linkname":
			nv.Status = domain.NegativeContradicted
			nv.Notes = fmt.Sprintf("symbol %s escapes static call graph via %s at %s:%d",
				subject.Package+"."+subject.Symbol, m.Kind, m.File, m.Line)
			return setNeg(claim, nv)
		case "reflect", "unsafe", "plugin":
			nv.Limitations = append(nv.Limitations,
				m.Kind+" usage in product widens the call graph; static negative verification is weaker")
		}
	}

	switch cond.Kind {
	case domain.ConditionSymbolReachable:
		return v.verifyReachableFalse(claim, nv, subject, sites)
	case domain.ConditionAttackerControl, domain.ConditionInputConstraint:
		return v.verifyInputFalse(ctx, c, claim, nv, subject, cond.ArgIndex)
	default:
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "no falsification strategy for condition kind " + string(cond.Kind)
		return setNeg(claim, nv)
	}
}

// verifyReachableFalse: govulncheck reported no call path. A FALSE survives
// only when the symbol has no references at all; any static reference without
// a call path could still execute via an un-modeled entrypoint or dispatch.
func (v Verifier) verifyReachableFalse(claim domain.Claim,
	nv *domain.NegativeVerification, subject domain.SymbolRef, sites []domain.CallSite) domain.Claim {

	if len(sites) == 0 {
		nv.Notes = "symbol has no references in product code; call path impossible by static evidence"
		return setNeg(claim, nv)
	}
	nv.Status = domain.NegativeInsufficientScope
	nv.Notes = fmt.Sprintf("%d static reference(s) to %s exist without a govulncheck path; "+
		"cannot exclude dynamic dispatch or un-modeled entrypoints",
		len(sites), subject.Package+"."+subject.Symbol)
	return setNeg(claim, nv)
}

// verifyInputFalse verifies the FALSE candidate for ATTACKER_CONTROL /
// INPUT_CONSTRAINT: every call site of the sink must pass an argument whose
// provenance resolves to a non-external origin.
func (v Verifier) verifyInputFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification, subject domain.SymbolRef, argIndex int) domain.Claim {

	callers, err := v.Source.FindCallers(ctx, subject)
	if err != nil {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "caller search failed: " + err.Error()
		return setNeg(claim, nv)
	}
	if len(callers) == 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "no direct call sites found; indirect invocation possible"
		return setNeg(claim, nv)
	}
	for _, site := range callers {
		flow, evs, err := v.Source.TraceArgument(ctx, site, argIndex)
		if err != nil {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "provenance failed at " + site.Function + ": " + err.Error()
			return setNeg(claim, nv)
		}
		for _, e := range evs {
			nv.EvidenceIDs = append(nv.EvidenceIDs, c.EvidenceGraph.AddEvidence(e))
		}
		if flow.Origin == domain.OriginUnknown ||
			flow.Origin == domain.OriginExternalUntrusted ||
			flow.Origin == domain.OriginExternalAuthenticated {
			nv.Status = domain.NegativeContradicted
			nv.Notes = fmt.Sprintf("call site %s passes %s input (%s); FALSE contradicted",
				site.Function, flow.Origin, flow.Summary)
			return setNeg(claim, nv)
		}
	}
	nv.Notes = fmt.Sprintf("all %d call site(s) pass non-external input", len(callers))
	return setNeg(claim, nv)
}

func setNeg(cl domain.Claim, nv *domain.NegativeVerification) domain.Claim {
	cl.NegativeVerification = nv
	if nv.Status == domain.NegativeContradicted {
		cl.Result = domain.ClaimUnknown
		cl.Explanation += " | negative verification contradicted: " + nv.Notes
	}
	return cl
}
