package goanalysis

import (
	"context"
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Verifier performs a bounded negative verification pass on FALSE claims.
// It searches for alternate references, dynamic escapes and provenance
// bypasses that static analysis may have missed. A FALSE claim only survives
// when the falsification pass finds no counterexample within the searchable
// scope; contradictions demote it back to UNKNOWN.
// verifyHops bounds the re-trace budget negative verification uses when
// re-deriving argument origins — the same budget gap analysis applies,
// so a claim resolved by a deep trace is not re-judged on a shallow one.
const verifyHops = 16

type Verifier struct {
	Source *Index
}

// VerifyFalse attempts to falsify a FALSE claim for cond across all of its
// subjects and returns the updated claim with its NegativeVerification.
func (v Verifier) VerifyFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	cond domain.Condition) domain.Claim {

	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	if v.Source == nil {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "source index not configured",
		})
	}
	subjects := append([]domain.SymbolRef{}, cond.Subjects...)
	if cond.Subject != nil {
		subjects = append(subjects, *cond.Subject)
	}
	if len(subjects) == 0 && c.Exploit != nil {
		subjects = append(subjects, c.Exploit.RootCauses...)
	}
	if len(subjects) == 0 && c.RootCause != nil {
		for _, rc := range c.RootCause.RootCauses {
			subjects = append(subjects, domain.SymbolRef{Package: rc.Package, Symbol: rc.Symbol})
		}
	}
	if len(subjects) == 0 {
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "no subject symbols on condition",
		})
	}

	// Parametric checks (config knobs, exposure, symbol presence) are
	// falsified by their own evidence, not by subject-escape rules — the
	// subjects bound to such conditions are advisory sinks, and a
	// func_value marker on a sink says nothing about the knob's value.
	switch cond.Params[domain.ParamCheck] {
	case domain.CheckConfigFlag, domain.CheckConfigKey,
		domain.CheckExposure, domain.CheckSymbolPresent:
		return setNeg(claim, &domain.NegativeVerification{
			Status: domain.NegativeInsufficientScope,
			Notes:  "parametric check condition — subject-escape falsification does not apply",
		})
	}

	allSites := map[string][]domain.CallSite{}
	anyExported := false
	for _, s := range subjects {
		if symbolExported(s) {
			anyExported = true
		}
	}
	dynSeen := map[string]bool{}
	var strayLinkname int
	for _, subj := range subjects {
		sites, err := v.Source.SearchSymbol(ctx, subj)
		if err != nil {
			return setNeg(claim, &domain.NegativeVerification{
				Status: domain.NegativeInsufficientScope,
				Notes:  "symbol search failed: " + err.Error(),
			})
		}
		allSites[subj.Package+"."+subj.Symbol] = sites

		markers, err := v.Source.ScanDynamic(ctx, subj)
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
			case "func_value":
				nv.Status = domain.NegativeContradicted
				nv.Notes = fmt.Sprintf("symbol %s escapes static call graph via %s at %s:%d",
					subj.Package+"."+subj.Symbol, m.Kind, m.File, m.Line)
				return setNeg(claim, nv)
			case "linkname":
				// go:linkname contradicts only when it targets this symbol —
				// an unrelated pragma cannot invoke it.
				if strings.Contains(m.Detail, subj.Package) || linknameNames(m.Detail, subj) {
					nv.Status = domain.NegativeContradicted
					nv.Notes = fmt.Sprintf("symbol %s escapes static call graph via go:linkname at %s:%d",
						subj.Package+"."+subj.Symbol, m.File, m.Line)
					return setNeg(claim, nv)
				}
				strayLinkname++
			case "reflect", "unsafe", "plugin":
				// reflect/plugin can only look up *exported* identifiers; an
				// unexported sink is unreachable to them.
				// For guard-based FALSE claims bare reflect/unsafe imports
				// are irrelevant: an import cannot write the guarded value —
				// only reflect_write (Value.Set*) and unsafe_write
				// (store through unsafe.Pointer deref) markers can.
				if (m.Kind == "reflect" || m.Kind == "unsafe") &&
					claim.Falsifier == "guards" {
					continue
				}
				if anyExported && !dynSeen[m.Kind] {
					dynSeen[m.Kind] = true
					nv.Limitations = append(nv.Limitations,
						m.Kind+" usage in product widens the call graph; static negative verification is weaker")
				}
			case "reflect_write":
				// A Set* call can mutate a guarded field out of sight of
				// syntactic write-site scans — but reflect.Set works only on
				// *exported* fields; when every covered field is unexported
				// this marker cannot invalidate the coverage.
				if claim.Falsifier == "guards" && !hasExportedCoveredField(c, claim) {
					continue
				}
				if !dynSeen[m.Kind] {
					dynSeen[m.Kind] = true
					nv.Limitations = append(nv.Limitations,
						"reflect.Value.Set* call at "+m.File+":"+fmt.Sprint(m.Line)+
							" can write fields invisibly; guard coverage is weaker")
				}
			case "unsafe_write", "unsafe_ptr":
				// A store through an unsafe.Pointer-derived value — or a
				// materialized raw pointer whose aliased writes cannot be
				// traced — can write *any* field, including unexported ones,
				// so it weakens guard coverage unconditionally.
				if !dynSeen[m.Kind] {
					dynSeen[m.Kind] = true
					nv.Limitations = append(nv.Limitations,
						m.Detail+" at "+m.File+":"+fmt.Sprint(m.Line)+
							"; guard coverage is weaker")
				}
			}
		}
	}
	if strayLinkname > 0 {
		nv.Notes += fmt.Sprintf(" %d unrelated go:linkname pragma(s) ignored", strayLinkname)
	}

	var out domain.Claim
	switch {
	case cond.Kind == domain.ConditionSymbolReachable &&
		cond.Params[domain.ParamDirection] == domain.DirectionRead:
		out = v.verifyReadFalse(claim, nv, subjects, allSites)
	case cond.Kind == domain.ConditionSymbolReachable &&
		cond.Params[domain.ParamSequence] != "":
		out = v.verifySequenceFalse(c, claim, nv, subjects, allSites)
	default:
		switch cond.Kind {
		case domain.ConditionSymbolReachable:
			out = v.verifyReachableFalse(claim, nv, subjects, allSites)
		case domain.ConditionAttackerControl:
			out = v.verifyInputFalse(ctx, c, claim, nv, subjects, cond.ArgIndex)
		case domain.ConditionInputConstraint:
			if claim.Falsifier == "guards" {
				out = v.verifyGuardFalse(ctx, c, claim, nv)
			} else {
				out = v.verifyInputFalse(ctx, c, claim, nv, subjects, cond.ArgIndex)
			}
		case domain.ConditionValidation:
			out = v.verifyGuardFalse(ctx, c, claim, nv)
		case domain.ConditionPlatform, domain.ConditionRuntime:
			out = verifySnapshotFalse(claim, nv)
		default:
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "no falsification strategy for condition kind " + string(cond.Kind)
			out = setNeg(claim, nv)
		}
	}
	// A VERIFIED negative is scoped to what the loaded index can see:
	// extend the scope to build-tag-excluded files and interface
	// dispatch before letting a verdict rely on it.
	if out.NegativeVerification != nil &&
		out.NegativeVerification.Status == domain.NegativeVerified {
		v.extendNegativeScope(ctx, c, out.NegativeVerification, subjects)
	}
	return out
}

// extendNegativeScope widens the negative check beyond the typed index:
// references in files excluded by the current build tags, and call sites
// where the subject's method could be reached through interface
// dispatch. Either finding downgrades VERIFIED to INSUFFICIENT_SCOPE —
// they show an un-closed scope, not a proven path, so the claim's FALSE
// result is kept but cannot support the verdict.
func (v Verifier) extendNegativeScope(ctx context.Context, c *domain.AnalysisCase,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef) {

	addSites := func(tool string, sites []domain.CallSite) {
		for _, s := range sites {
			nv.EvidenceIDs = append(nv.EvidenceIDs, c.EvidenceGraph.AddEvidence(domain.Evidence{
				Kind:    domain.EvidenceSourceSnippet,
				Quality: domain.QualityDeterministic,
				Source:  "go-analysis " + tool,
				Tool:    "goanalysis.Index",
				Content: fmt.Sprintf("%s.%s referenced at %s:%d", s.Package, s.Function, s.File, s.Line),
			}))
		}
	}
	for _, subj := range subjects {
		gated, err := v.Source.GatedRefs(ctx, subj)
		if err != nil {
			nv.Limitations = append(nv.Limitations, "build-tag-excluded scan failed: "+err.Error())
			continue
		}
		if len(gated) > 0 {
			addSites("GatedRefs", gated)
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes += fmt.Sprintf(" %d reference(s) to %s.%s in files excluded by the current build tags — an alternate build configuration may reach the subject;",
				len(gated), subj.Package, subj.Symbol)
		}
		disp, err := v.Source.InterfaceDispatchSites(ctx, subj)
		if err != nil {
			nv.Limitations = append(nv.Limitations, "interface dispatch scan failed: "+err.Error())
			continue
		}
		if len(disp) > 0 {
			addSites("InterfaceDispatchSites", disp)
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes += fmt.Sprintf(" %d interface-dispatched call site(s) may invoke %s.%s — the concrete implementation behind an interface is not resolved;",
				len(disp), subj.Package, subj.Symbol)
		}
	}
}

// verifyReadFalse falsifies a direction=read FALSE ("no product reader of
// the exposed datum"): any static product reference to a subject IS a
// reader candidate, so it contradicts the FALSE outright rather than
// merely weakening it.
func (v Verifier) verifyReadFalse(claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef,
	allSites map[string][]domain.CallSite) domain.Claim {

	var total int
	for _, s := range subjects {
		total += len(allSites[s.Package+"."+s.Symbol])
	}
	if total == 0 {
		nv.Notes = fmt.Sprintf("none of %d subject(s) is referenced in product code",
			len(subjects))
		return setNeg(claim, nv)
	}
	nv.Status = domain.NegativeContradicted
	nv.Notes = fmt.Sprintf("%d product reference(s) to the subject(s) exist — reader candidates the FALSE did not see",
		total)
	return setNeg(claim, nv)
}

// verifySequenceFalse falsifies a sequence FALSE ("the round-trip pair is
// incomplete"). Only the never-invoked members can resurrect it: if the
// product still statically references them, an indirect invocation path
// cannot be excluded.
func (v Verifier) verifySequenceFalse(c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef,
	allSites map[string][]domain.CallSite) domain.Claim {

	var missing []string
	for _, s := range subjects {
		key := s.Package + "." + s.Symbol
		if _, ok := c.EvidenceGraph.ModuleReachable[key]; ok {
			continue
		}
		called := false
		for _, u := range c.EvidenceGraph.ModuleUsages {
			if u.Callee == key {
				called = true
				break
			}
		}
		if !called {
			missing = append(missing, key)
		}
	}
	refs := 0
	for _, m := range missing {
		refs += len(allSites[m])
	}
	if refs == 0 {
		nv.Notes = fmt.Sprintf("never-invoked member(s) %s have no product references",
			strings.Join(missing, ", "))
		return setNeg(claim, nv)
	}
	nv.Status = domain.NegativeInsufficientScope
	nv.Notes = fmt.Sprintf("%d product reference(s) to never-invoked member(s) exist; "+
		"cannot exclude indirect invocation", refs)
	return setNeg(claim, nv)
}

// verifyReachableFalse: govulncheck reported no call path. A FALSE survives
// only when no subject has references at all; any static reference without
// a call path could still execute via an un-modeled entrypoint or dispatch.
func (v Verifier) verifyReachableFalse(claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef,
	allSites map[string][]domain.CallSite) domain.Claim {

	total := 0
	for _, s := range subjects {
		total += len(allSites[s.Package+"."+s.Symbol])
	}
	if total == 0 {
		nv.Notes = fmt.Sprintf("none of %d affected symbol(s) is referenced in product code",
			len(subjects))
		return setNeg(claim, nv)
	}
	nv.Status = domain.NegativeInsufficientScope
	nv.Notes = fmt.Sprintf("%d static reference(s) across %d subject(s) exist without a govulncheck path; "+
		"cannot exclude dynamic dispatch or un-modeled entrypoints", total, len(subjects))
	return setNeg(claim, nv)
}

// verifyInputFalse verifies the FALSE candidate for ATTACKER_CONTROL /
// INPUT_CONSTRAINT: every call site of every subject must pass arguments
// whose provenance resolves to a non-external origin (argIndex < 0 covers
// all arguments).
func (v Verifier) verifyInputFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification, subjects []domain.SymbolRef, argIndex int) domain.Claim {

	totalCallers := 0
	for _, subj := range subjects {
		callers, err := v.Source.FindCallers(ctx, subj)
		if err != nil {
			nv.Status = domain.NegativeInsufficientScope
			nv.Notes = "caller search failed: " + err.Error()
			return setNeg(claim, nv)
		}
		if len(callers) == 0 && c.Vulnerability.Module != "" &&
			(subj.Package == c.Vulnerability.Module ||
				strings.HasPrefix(subj.Package, c.Vulnerability.Module+"/")) {
			// Unexported dependency subjects have no product callers — the
			// FALSE under verification may have been produced by dep-internal
			// provenance; re-trace the same dep scope.
			depCallers, derr := v.Source.FindDepCallers(ctx, subj)
			if derr != nil {
				nv.Status = domain.NegativeInsufficientScope
				nv.Notes = "dep caller search failed: " + derr.Error()
				return setNeg(claim, nv)
			}
			callers = depCallers
		}
		if len(callers) == 0 {
			continue // no direct call sites of this subject; others may still contradict
		}
		totalCallers += len(callers)
		for _, site := range callers {
			var flows []domain.DataFlow
			var evs []domain.Evidence
			var err error
			if argIndex < 0 {
				flows, evs, err = v.Source.TraceAllArgumentsBound(ctx, site, verifyHops)
			} else {
				var f domain.DataFlow
				f, evs, err = v.Source.TraceArgumentBound(ctx, site, argIndex, verifyHops)
				flows = []domain.DataFlow{f}
			}
			if err != nil {
				nv.Status = domain.NegativeInsufficientScope
				nv.Notes = "provenance failed at " + site.Function + ": " + err.Error()
				return setNeg(claim, nv)
			}
			for _, e := range evs {
				nv.EvidenceIDs = append(nv.EvidenceIDs, c.EvidenceGraph.AddEvidence(e))
			}
			for _, flow := range flows {
				switch flow.Origin {
				case domain.OriginExternalUntrusted, domain.OriginExternalAuthenticated,
					domain.OriginConfiguration, domain.OriginDatabase,
					domain.OriginInternalService:
					nv.Status = domain.NegativeContradicted
					nv.Notes = fmt.Sprintf("call site %s passes %s input (%s); FALSE contradicted",
						site.Function, flow.Origin, flow.Summary)
					return setNeg(claim, nv)
				case domain.OriginUnknown, "":
					// Absence of evidence is not a contradiction: the
					// verifier could not resolve this argument — scope
					// insufficient to confirm the FALSE, not disproven.
					nv.Status = domain.NegativeInsufficientScope
					nv.Notes = fmt.Sprintf("call site %s argument %d unresolvable (%s); cannot verify FALSE",
						site.Function, flow.Arg, flow.Summary)
					return setNeg(claim, nv)
				}
			}
		}
	}
	if totalCallers == 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "no direct call sites found for any subject; indirect invocation possible"
		return setNeg(claim, nv)
	}
	nv.Notes = fmt.Sprintf("all %d call site(s) across %d subject(s) pass non-external input",
		totalCallers, len(subjects))
	return setNeg(claim, nv)
}

// verifyGuardFalse verifies a VALIDATION FALSE ("every path to the sink is
// guarded"). The claim stands only when every traced sink site carries a
// Covers validation emitted by the bounded caller-guard climb — i.e. all
// expanded caller branches guard the argument. Missing sinks or partial
// coverage are INSUFFICIENT_SCOPE, not contradictions. extendNegativeScope
// still applies: a dynamic or build-gated call into the sink bypasses
// caller guards entirely.
func (v Verifier) verifyGuardFalse(ctx context.Context, c *domain.AnalysisCase, claim domain.Claim,
	nv *domain.NegativeVerification) domain.Claim {

	// (sink, arg) pairs recorded for this claim's condition — a guard on
	// arg0 must not certify arg1 of the same call.
	type sinkRef struct {
		site   domain.CallSite
		arg    int
		origin domain.DataOrigin
	}
	sinks := map[string]sinkRef{}
	for _, f := range c.EvidenceGraph.DataFlows {
		if claim.ConditionID != "" && f.ConditionID != claim.ConditionID {
			continue
		}
		key := fmt.Sprintf("%s:%d:%d", f.Sink.File, f.Sink.Line, f.Arg)
		sinks[key] = sinkRef{f.Sink, f.Arg, f.Origin}
	}
	if len(sinks) == 0 {
		// Older producers may record flows without a condition id.
		for _, f := range c.EvidenceGraph.DataFlows {
			key := fmt.Sprintf("%s:%d:%d", f.Sink.File, f.Sink.Line, f.Arg)
			sinks[key] = sinkRef{f.Sink, f.Arg, f.Origin}
		}
	}
	if len(sinks) == 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "no sink call sites recorded for the validation claim"
		return setNeg(claim, nv)
	}
	var uncovered []string
	var gated []string
	var conditional []string
	for key, s := range sinks {
		// A constant or generated argument is bounded by definition —
		// it needs no guard to certify it cannot violate the constraint.
		if s.origin == domain.OriginConstant || s.origin == domain.OriginGenerated {
			continue
		}
		guarded := false
		var condSites []domain.CallSite
		for _, val := range c.EvidenceGraph.Validations {
			// An Arg-scoped record constrains only that argument of the
			// sink call; Arg < 0 marks a record covering any position.
			if val.Arg >= 0 && s.arg >= 0 && val.Arg != s.arg {
				continue
			}
			if val.Covers != nil && val.Covers.File == s.site.File && val.Covers.Line == s.site.Line {
				guarded = true
				continue
			}
			// Only genuine guards can cover a sink — origin-assignment
			// records (Guard=false) just document where the value came
			// from. A guard nested in control flow is conditional: it
			// covers the sink only when the enclosing condition holds,
			// which is not something a FALSE claim may assume.
			if !val.Guard || val.File != s.site.File || val.Line <= 0 || val.Line >= s.site.Line {
				continue
			}
			if val.Conditional {
				condSites = append(condSites, val.CallSite)
				continue
			}
			guarded = true
		}
		if guarded {
			continue
		}
		// Conditional guards are the only records for this sink: check
		// whether the enclosing condition reads configuration — a knob the
		// analysis may not have resolved (spec §19 configuration
		// overrides). Downgrade either way, never silently accept.
		if len(condSites) > 0 {
			configHit := false
			if v.Source != nil {
				for _, gs := range condSites {
					if g, detail, err := v.Source.ConfigGated(ctx, gs); err == nil && g {
						configHit = true
						gated = append(gated, detail)
					}
				}
			}
			if !configHit {
				for _, gs := range condSites {
					conditional = append(conditional,
						fmt.Sprintf("%s:%d", gs.File, gs.Line))
				}
			}
			continue
		}
		uncovered = append(uncovered, key)
	}
	if len(gated) > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "covering guard(s) are conditional on configuration: " + strings.Join(gated, "; ")
		return setNeg(claim, nv)
	}
	if len(conditional) > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "guard(s) only hold under enclosing control-flow conditions: " +
			strings.Join(conditional, ", ")
		return setNeg(claim, nv)
	}
	if len(uncovered) > 0 {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = fmt.Sprintf("%d sink site(s) lack a covering guard: %s",
			len(uncovered), strings.Join(uncovered, ", "))
		return setNeg(claim, nv)
	}
	nv.Notes = fmt.Sprintf("all %d sink site(s) are covered by guards", len(sinks))
	return setNeg(claim, nv)
}

// hasExportedCoveredField reports whether any guard covering this claim's
// sinks protects an exported field — the only kind reflect.Value.Set can
// mutate. Unexported fields and claims with no field-backed guards return
// false: reflect cannot write locals or unexported fields, so there is
// nothing for a reflect_write marker to weaken.
func hasExportedCoveredField(c *domain.AnalysisCase, claim domain.Claim) bool {
	for _, val := range c.EvidenceGraph.Validations {
		if claim.ConditionID != "" &&
			!strings.Contains(val.Property, "cond="+string(claim.ConditionID)) {
			continue
		}
		name := ""
		firstField := func(rest string) string {
			if f := strings.Fields(rest); len(f) > 0 {
				return f[0]
			}
			return ""
		}
		if i := strings.Index(val.Property, "field-write "); i >= 0 {
			name = strings.TrimSuffix(firstField(val.Property[i+len("field-write "):]), ":")
		} else if i := strings.Index(val.Property, "write site of field "); i >= 0 {
			name = firstField(val.Property[i+len("write site of field "):])
		}
		if name == "" {
			continue
		}
		if name[0] >= 'A' && name[0] <= 'Z' {
			return true
		}
	}
	return false
}

func setNeg(cl domain.Claim, nv *domain.NegativeVerification) domain.Claim {
	cl.NegativeVerification = nv
	if nv.Status == domain.NegativeContradicted {
		cl.Result = domain.ClaimUnknown
		cl.Explanation += " | negative verification contradicted: " + nv.Notes
	}
	return cl
}

// symbolExported reports whether the subject name is an exported identifier
// (receiver-qualified subjects are split on the last dot).
func symbolExported(s domain.SymbolRef) bool {
	name := s.Symbol
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		name = name[i+1:]
	}
	return name != "" && name[0] >= 'A' && name[0] <= 'Z'
}

// linknameNames reports whether a go:linkname pragma targets the subject.
func linknameNames(detail string, s domain.SymbolRef) bool {
	return strings.Contains(detail, s.Symbol)
}

// verifySnapshotFalse accepts FALSE claims that are decided by snapshot
// facts (platform, runtime toolchain) rather than code-scope searches:
// there is no call-site scope to widen, so the negative is VERIFIED when
// the evaluator produced a mismatch explanation.
func verifySnapshotFalse(claim domain.Claim, nv *domain.NegativeVerification) domain.Claim {
	if claim.Explanation == "" {
		nv.Status = domain.NegativeInsufficientScope
		nv.Notes = "FALSE without a recorded snapshot-fact mismatch"
		return setNeg(claim, nv)
	}
	nv.Notes = "FALSE is decided by product snapshot facts, not call-site scope"
	return setNeg(claim, nv)
}
