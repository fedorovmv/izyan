package evaluator

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// ServerTransportInput evaluates ATTACKER_CONTROL / INPUT_CONSTRAINT for
// vulnerabilities whose reachable sink is a server-side transport loop
// (e.g. gRPC http2Server.HandleStreams). When a govulncheck call path reaches
// such a frame, the bytes the sink consumes originate from remote clients of
// the product's listener — the input is attacker-controlled by construction,
// not by a product-code argument.
//
// The claim is TRUE with a limitation: whether an attacker can actually reach
// the listener (bind address, service exposure, mTLS) is a deployment
// property the code cannot prove.
type ServerTransportInput struct{}

func (ServerTransportInput) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionAttackerControl || cond.Kind == domain.ConditionInputConstraint
}

func (ServerTransportInput) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	// A declared non-peer input source skips transport reasoning entirely:
	// the pattern asserts the input arrives as an argument or from config.
	if src := cond.Params[domain.ParamInputSource]; src == domain.InputArg || src == domain.InputConfig {
		return ArgumentOrigin{}.Evaluate(cond, c)
	}
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.ServerTransportInput",
	}
	if c.Product.TrustedPeer && wantsPeerInput(cond, c.Vulnerability) {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierTrustedInfrastructure
		claim.Explanation = "deployment infrastructure declared trusted peer communication (--trusted-peer): network traffic and remote peers/brokers are authenticated and trusted"
		claim.NegativeVerification = &domain.NegativeVerification{
			Status: domain.NegativeVerified,
			Notes:  "deployment infrastructure declared trusted peer communication (--trusted-peer)",
		}
		return claim
	}
	module := c.Vulnerability.Module
	var frames []string
	var evIDs []domain.EvidenceID
	for _, cp := range c.EvidenceGraph.CallPaths {
		for _, fr := range cp.Frames {
			if !isServerTransportFrame(fr, module) {
				continue
			}
			frames = appendUnique(frames, frameName(fr))
			if cp.EvidenceID != "" {
				evIDs = appendUniqueID(evIDs, cp.EvidenceID)
			}
		}
	}
	if len(frames) == 0 {
		for _, chain := range c.EvidenceGraph.ModuleReachable {
			for _, sym := range chain {
				fr := parseSymbolToCallSite(sym)
				if !isServerTransportFrame(fr, module) {
					continue
				}
				frames = appendUnique(frames, frameName(fr))
				for _, id := range moduleReachEvidence(c) {
					evIDs = appendUniqueID(evIDs, id)
				}
			}
		}
	}
	if len(frames) == 0 {
		// Dep-internal argument provenance recorded for this condition
		// outranks the structural heuristic below: a resolved origin —
		// external or not — is decided by the real trace, while a trace
		// that stayed UNKNOWN everywhere leaves the heuristic as fallback.
		if hasResolvedFlows(c, cond.ID) {
			return ArgumentOrigin{}.Evaluate(cond, c)
		}
		// Client side: the product calls the vulnerable module's API, so
		// unexported internals run inside its peer-driven read path — input
		// is controlled by the remote peer (broker/server), not product code.
		// Applies when the condition is about peer input — declared via
		// input_source=peer or inferred from remote-input wording.
		// Usage sites are filtered to the subject-owning modules — a call
		// into a different linked module is no evidence here either.
		if subs := reachabilitySubjects(cond, c); subs != nil && allUnexported(subs) &&
			wantsPeerInput(cond, c.Vulnerability) {
			usages, _ := subjectModuleUsages(c, subs)
			if len(usages) == 0 {
				return ArgumentOrigin{}.Evaluate(cond, c)
			}
			claim.Result = domain.ClaimTrue
			claim.EvidenceIDs = moduleUsageEvidence(c)
			claim.Explanation = fmt.Sprintf(
				"product calls the subject-owning module's API at %d site(s); unexported transport internals consume peer-controlled input",
				len(usages))
			claim.Limitations = append(claim.Limitations,
				"peer identity/trust is a deployment property — TRUE assumes the remote endpoint is attacker-influenced")
			return claim
		}
		// Not a transport vulnerability — defer to argument provenance.
		return ArgumentOrigin{}.Evaluate(cond, c)
	}
	for _, e := range c.EvidenceGraph.Entrypoints {
		if e.Kind == "listener" {
			frames = appendUnique(frames, "listener "+e.Package+"."+e.Function+" ("+e.Detail+")")
		}
	}
	if c.Product.TrustedPeer {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = domain.FalsifierTrustedInfrastructure
		claim.EvidenceIDs = evIDs
		claim.Explanation = fmt.Sprintf(
			"reachable server transport (%s) in trusted infrastructure (--trusted-peer): inbound clients are authenticated and trusted",
			strings.Join(frames, ", "))
		claim.NegativeVerification = &domain.NegativeVerification{
			Status: domain.NegativeVerified,
			Notes:  "deployment infrastructure declared trusted peer communication (--trusted-peer)",
		}
		return claim
	}
	claim.Result = domain.ClaimTrue
	claim.EvidenceIDs = evIDs
	claim.Explanation = fmt.Sprintf(
		"reachable server transport (%s): inbound bytes originate from remote clients of the product's listener",
		strings.Join(frames, ", "))
	claim.Limitations = append(claim.Limitations,
		"listener bind address and exposure scope are configuration/deployment-dependent — TRUE assumes an attacker can connect")
	return claim
}

// isServerTransportFrame reports whether a call-path frame inside the
// vulnerable module is a server-side transport routine: the code that reads
// peer-controlled bytes off a socket. Product-side helpers coincidentally
// named Serve/Accept do not qualify — only frames within the vuln module.
func isServerTransportFrame(fr domain.CallSite, module string) bool {
	if module != "" && fr.Package != module && !strings.HasPrefix(fr.Package, module+"/") {
		return false
	}
	if strings.Contains(fr.Receiver, "Server") || strings.Contains(fr.Receiver, "server") {
		return true
	}
	switch fr.Function {
	case "Serve", "ServeHTTP", "Accept", "HandleStreams", "NewServerTransport", "newServerTransport":
		return true
	}
	return false
}

// remoteInputRe hints that the condition is about peer/network-controlled
// input — required for the client-transport rule to fire.
var remoteInputRe = regexp.MustCompile(`(?i)remote|peer|server|broker|network|unauthenticated|frame|packet|malformed`)

func describesRemoteInput(cond domain.Condition, v domain.Vulnerability) bool {
	return remoteInputRe.MatchString(cond.Description) ||
		remoteInputRe.MatchString(v.Summary) ||
		remoteInputRe.MatchString(v.Description)
}

// WantsPeerInput exposes the peer-input predicate for the evidence
// collector's dep-scope gate — same semantics as wantsPeerInput.
func WantsPeerInput(cond domain.Condition, v domain.Vulnerability) bool {
	return wantsPeerInput(cond, v)
}

// wantsPeerInput reports whether the condition is about peer-controlled
// input. An explicit input_source param outranks the description regex —
// patterns declare peer input even when the condition text carries no
// remote-signal words.
func wantsPeerInput(cond domain.Condition, v domain.Vulnerability) bool {
	if cond.Params[domain.ParamInputSource] == domain.InputPeer {
		return true
	}
	return describesRemoteInput(cond, v)
}

// hasResolvedFlows reports whether any data flow recorded for this
// condition resolved to a concrete origin — dep-internal traces with a
// real answer take precedence over the unexported+peer-driven heuristic.
func hasResolvedFlows(c *domain.AnalysisCase, id domain.ConditionID) bool {
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.ConditionID == id && f.Origin != "" && f.Origin != domain.OriginUnknown {
			return true
		}
	}
	return false
}

func frameName(fr domain.CallSite) string {
	if fr.Receiver != "" {
		return fr.Package + "." + fr.Receiver + "." + fr.Function
	}
	return fr.Package + "." + fr.Function
}

func appendUnique(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

func parseSymbolToCallSite(sym string) domain.CallSite {
	lastDot := strings.LastIndexByte(sym, '.')
	if lastDot < 0 {
		return domain.CallSite{Function: sym}
	}
	fn := sym[lastDot+1:]
	rest := sym[:lastDot]
	lastSlash := strings.LastIndexByte(rest, '/')
	sub := rest
	if lastSlash >= 0 {
		sub = rest[lastSlash+1:]
	}
	if midDot := strings.IndexByte(sub, '.'); midDot >= 0 {
		pkg := rest[:len(rest)-len(sub)+midDot]
		recv := sub[midDot+1:]
		return domain.CallSite{Package: pkg, Receiver: recv, Function: fn}
	}
	return domain.CallSite{Package: rest, Function: fn}
}
