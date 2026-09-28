package evaluator

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func reachabilityCase() *domain.AnalysisCase {
	c := &domain.AnalysisCase{}
	c.Vulnerability = domain.Vulnerability{
		ID: "GO-TEST-1",
		AffectedSymbols: []domain.SymbolRef{
			{Package: "lib/internal/transport", Symbol: "ServerStream.Read"},
		},
	}
	c.RootCause = &domain.RootCauseModel{
		RootCauses: []domain.RootCause{
			{Package: "lib/internal/transport", Symbol: "recvBuffer.put"},
		},
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{Kind: domain.EvidenceGovulncheck})
	return c
}

func TestSymbolReachableTrueViaAdvisorySymbol(t *testing.T) {
	c := reachabilityCase()
	cp := domain.CallPath{Frames: []domain.CallSite{
		{Package: "lib/internal/transport", Function: "Read", Receiver: "*ServerStream"},
		{Package: "lib", Function: "SendMsg", Receiver: "*clientStream"},
	}}
	c.EvidenceGraph.AddCallPath(cp)

	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID:   "C-REACH",
		Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE (govulncheck traced to advisory symbol)", claim.Result)
	}
}

func TestSymbolReachableFalseCandidateNoTrace(t *testing.T) {
	c := reachabilityCase()
	c.GovulncheckCoverage = "covered"
	// FALSE-candidate requires every evaluated subject to be declared in the
	// advisory's affected symbols — only those were actually traced.
	c.Vulnerability.AffectedSymbols = append(c.Vulnerability.AffectedSymbols,
		domain.SymbolRef{Package: "lib/internal/transport", Symbol: "recvBuffer.put"})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID:   "C-REACH",
		Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE candidate", claim.Result)
	}
}

// A covered advisory whose entry declares no affected symbols cannot have
// produced a symbol-level trace — its silence is not negative evidence,
// so the claim must fall back to module-usage instead of FALSE.
func TestSymbolReachableSymbollessCoveredNotFalse(t *testing.T) {
	c := reachabilityCase()
	c.GovulncheckCoverage = "covered"
	c.Vulnerability.AffectedSymbols = nil
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID:   "C-REACH",
		Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result == domain.ClaimFalse {
		t.Fatalf("got FALSE for a symbol-less advisory entry — govulncheck never evaluated the sink")
	}
}

// A subject outside the declared affected-symbol set was never traced by
// govulncheck — silence must not falsify it even when other subjects were
// declared and absent from the trace set.
func TestSymbolReachableUndeclaredSubjectNotFalse(t *testing.T) {
	c := reachabilityCase()
	c.GovulncheckCoverage = "covered"
	// reachabilityCase: declared {ServerStream.Read}, root cause
	// {recvBuffer.put} — the root cause was never in the DB symbol list.
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID:   "C-REACH",
		Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result == domain.ClaimFalse {
		t.Fatalf("got FALSE with undeclared subject recvBuffer.put")
	}
}

// A recorded intra-module chain from a product-used API proves
// reachability regardless of govulncheck trace coverage.
func TestSymbolReachableTrueViaModuleChain(t *testing.T) {
	c := reachabilityCase()
	c.GovulncheckCoverage = "covered"
	c.Vulnerability.AffectedSymbols = nil
	c.EvidenceGraph.AddEvidence(domain.Evidence{Tool: "goanalysis.Index.ModuleUsage"})
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{Package: "prod/x", Function: "DialTLS"})
	c.EvidenceGraph.AddModuleReachable("lib/internal/transport.recvBuffer.put", []string{
		"lib/transport.DialTLS", "lib/internal/transport.recvBuffer.put",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID:   "C-REACH",
		Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE: module-internal chain proves reach", claim.Result)
	}
}

func TestSymbolReachableUnknownNoGovulncheck(t *testing.T) {
	c := reachabilityCase()
	c.EvidenceGraph.Evidence = nil
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID:   "C-REACH",
		Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN when govulncheck did not run", claim.Result)
	}
}

func TestSymbolReachableWrongReceiverNoMatch(t *testing.T) {
	c := reachabilityCase()
	c.GovulncheckCoverage = "covered"
	c.Vulnerability.AffectedSymbols = append(c.Vulnerability.AffectedSymbols,
		domain.SymbolRef{Package: "lib/internal/transport", Symbol: "recvBuffer.put"})
	cp := domain.CallPath{Frames: []domain.CallSite{
		{Package: "lib/internal/transport", Function: "Read", Receiver: "*ClientStream"},
	}}
	c.EvidenceGraph.AddCallPath(cp)
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID:   "C-REACH",
		Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE candidate: receiver mismatch", claim.Result)
	}
}

func serverCase(frames []domain.CallSite) *domain.AnalysisCase {
	c := &domain.AnalysisCase{}
	c.Vulnerability = domain.Vulnerability{ID: "GO-T", Module: "lib/grpc"}
	c.EvidenceGraph.AddEvidence(domain.Evidence{Kind: domain.EvidenceGovulncheck})
	c.EvidenceGraph.AddCallPath(domain.CallPath{Frames: frames})
	return c
}

func TestServerTransportInputTrueOnServerFrame(t *testing.T) {
	c := serverCase([]domain.CallSite{
		{Package: "lib/grpc/internal/transport", Function: "HandleStreams", Receiver: "*http2Server"},
		{Package: "prod", Function: "Start", Receiver: "*Consumer"},
	})
	claim := ServerTransportInput{}.Evaluate(domain.Condition{
		ID: "C-ATTACK", Kind: domain.ConditionAttackerControl,
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE: server transport reached", claim.Result)
	}
	if len(claim.Limitations) == 0 {
		t.Fatal("expected exposure-scope limitation")
	}
}

func TestServerTransportInputIgnoresClientFrames(t *testing.T) {
	c := serverCase([]domain.CallSite{
		{Package: "lib/grpc/internal/transport", Function: "newStream", Receiver: "*http2Client"},
		{Package: "prod", Function: "Call"},
	})
	claim := ServerTransportInput{}.Evaluate(domain.Condition{
		ID: "C-ATTACK", Kind: domain.ConditionAttackerControl,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN: client-side path only", claim.Result)
	}
}

func TestServerTransportInputIgnoresProductServe(t *testing.T) {
	c := serverCase([]domain.CallSite{
		{Package: "prod/api", Function: "Serve", Receiver: "*Gateway"},
	})
	claim := ServerTransportInput{}.Evaluate(domain.Condition{
		ID: "C-ATTACK", Kind: domain.ConditionAttackerControl,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN: product Serve is not vuln-module transport", claim.Result)
	}
}

func affectedCase(ver string) *domain.AnalysisCase {
	c := &domain.AnalysisCase{}
	c.Affected = &domain.AffectedResult{
		VersionAffected: domain.ClaimTrue,
		ResolvedVersion: ver,
		EvidenceIDs:     []domain.EvidenceID{"EV-AFFECTED-MODULES"},
	}
	return c
}

func TestVersionFactPriorTo(t *testing.T) {
	c := affectedCase("v1.80.0")
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-BUILD", Kind: domain.ConditionBuild,
		Description: "The gRPC-Go version must be prior to 1.83.1 (the release containing the fix), or compaction must be disabled.",
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE", claim.Result)
	}
}

func TestVersionFactAbsentInVulnerable(t *testing.T) {
	c := affectedCase("v1.10.0")
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-CONF", Kind: domain.ConditionConfiguration,
		Description: "Buffer compaction must be absent. In vulnerable versions (< 1.13.0) the feature does not exist.",
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE", claim.Result)
	}
}

func TestVersionFactBoundNotSatisfied(t *testing.T) {
	c := affectedCase("v1.90.0")
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-BUILD", Kind: domain.ConditionBuild,
		Description: "version must be prior to 1.83.1",
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN: bound not satisfied", claim.Result)
	}
}

func TestVersionFactUnaffectedStaysUnknown(t *testing.T) {
	c := affectedCase("v1.80.0")
	c.Affected.VersionAffected = domain.ClaimUnknown
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-CONF", Kind: domain.ConditionConfiguration,
		Description: "in vulnerable versions the feature does not exist",
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN without proven affectedness", claim.Result)
	}
}

func rabbitCase() *domain.AnalysisCase {
	c := &domain.AnalysisCase{}
	c.Vulnerability = domain.Vulnerability{
		ID:     "GHSA-test",
		Module: "mod/amqp",
		AffectedSymbols: []domain.SymbolRef{
			{Package: "mod/amqp", Symbol: "readLongstr"},
		},
	}
	c.GovulncheckCoverage = "not_in_db"
	c.EvidenceGraph.AddEvidence(domain.Evidence{Kind: domain.EvidenceGovulncheck})
	// CollectEvidence always records the usage-scan marker when Source is
	// configured — even when zero call sites were found.
	c.EvidenceGraph.AddEvidence(domain.Evidence{Tool: "goanalysis.Index.ModuleUsage"})
	return c
}

func TestReachableNotInDBModuleUsedUnexported(t *testing.T) {
	c := rabbitCase()
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/amqp", Function: "DialTLS",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE: unexported sink + module usage", claim.Result)
	}
}

func TestReachableNotInDBNoUsageFalse(t *testing.T) {
	c := rabbitCase()
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE: module never called", claim.Result)
	}
}

func TestReachableNotInDBExportedUnknown(t *testing.T) {
	c := rabbitCase()
	c.Vulnerability.AffectedSymbols = []domain.SymbolRef{
		{Package: "mod/amqp", Symbol: "URI.String"},
	}
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/amqp", Function: "DialTLS",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN: exported sink needs per-symbol trace", claim.Result)
	}
}

func TestServerTransportClientSidePeerInput(t *testing.T) {
	c := rabbitCase()
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/amqp", Function: "DialTLS",
	})
	claim := ServerTransportInput{}.Evaluate(domain.Condition{
		ID: "C-ATTACK", Kind: domain.ConditionAttackerControl,
		Description: "A malicious or compromised AMQP server/broker sends crafted frames.",
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE: peer controls broker frames", claim.Result)
	}
}

func TestServerTransportClientSideNonRemoteStaysUnknown(t *testing.T) {
	c := rabbitCase()
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/amqp", Function: "DialTLS",
	})
	claim := ServerTransportInput{}.Evaluate(domain.Condition{
		ID: "C-FMT", Kind: domain.ConditionInputConstraint,
		Description: "The field value must exceed the maximum allowed length.",
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN: no remote-input signal", claim.Result)
	}
}
