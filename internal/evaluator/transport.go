package evaluator

import (
	"fmt"
	"regexp"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
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
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer:    "evaluator.ServerTransportInput",
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
		// Client side: the product calls the vulnerable module's API, so
		// unexported internals run inside its peer-driven read path — input
		// is controlled by the remote peer (broker/server), not product code.
		// Only applies when the condition describes remote input.
		if len(c.EvidenceGraph.ModuleUsages) > 0 && describesRemoteInput(cond, c.Vulnerability) &&
			reachabilitySubjects(cond, c) != nil && allUnexported(reachabilitySubjects(cond, c)) {
			claim.Result = domain.ClaimTrue
			claim.EvidenceIDs = moduleUsageEvidence(c)
			claim.Explanation = fmt.Sprintf(
				"product calls the vulnerable module's API at %d site(s); unexported transport internals consume peer-controlled input",
				len(c.EvidenceGraph.ModuleUsages))
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
