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
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{Package: "prod/x", Function: "DialTLS", Callee: "lib/transport.DialTLS", ModuleOwner: "lib/transport"})
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

func TestServerTransportInputTrustedPeerFalse(t *testing.T) {
	c := serverCase([]domain.CallSite{
		{Package: "lib/grpc/internal/transport", Function: "HandleStreams", Receiver: "*http2Server"},
		{Package: "prod", Function: "Start", Receiver: "*Consumer"},
	})
	c.Product.TrustedPeer = true
	claim := ServerTransportInput{}.Evaluate(domain.Condition{
		ID: "C-ATTACK", Kind: domain.ConditionAttackerControl,
	}, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE: trusted peer deployment declared", claim.Result)
	}
	if claim.Falsifier != domain.FalsifierTrustedInfrastructure {
		t.Fatalf("got falsifier %q, want %q", claim.Falsifier, domain.FalsifierTrustedInfrastructure)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected negative verification VERIFIED, got: %+v", claim.NegativeVerification)
	}
}

func TestServerTransportInputTrustedPeerWantsPeerInputFalse(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.Product.TrustedPeer = true
	claim := ServerTransportInput{}.Evaluate(domain.Condition{
		ID: "C-PEER-INPUT", Kind: domain.ConditionAttackerControl,
		Params: map[string]string{domain.ParamInputSource: domain.InputPeer},
	}, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE: trusted peer deployment declared", claim.Result)
	}
	if claim.Falsifier != domain.FalsifierTrustedInfrastructure {
		t.Fatalf("got falsifier %q, want %q", claim.Falsifier, domain.FalsifierTrustedInfrastructure)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected negative verification VERIFIED, got: %+v", claim.NegativeVerification)
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
		Package: "prod/amqp", Function: "DialTLS", Callee: "mod/amqp.DialTLS", ModuleOwner: "mod/amqp",
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
		Package: "prod/amqp", Function: "DialTLS", Callee: "mod/amqp.DialTLS", ModuleOwner: "mod/amqp",
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
		Package: "prod/amqp", Function: "DialTLS", Callee: "mod/amqp.DialTLS", ModuleOwner: "mod/amqp",
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
		Package: "prod/amqp", Function: "DialTLS", Callee: "mod/amqp.DialTLS", ModuleOwner: "mod/amqp",
	})
	claim := ServerTransportInput{}.Evaluate(domain.Condition{
		ID: "C-FMT", Kind: domain.ConditionInputConstraint,
		Description: "The field value must exceed the maximum allowed length.",
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN: no remote-input signal", claim.Result)
	}
}

// Under a multi-module advisory a product call into module A is not
// evidence for an unexported subject in module B — usage sites are
// attributed to the subject-owning module before the verdict.
func TestModuleUsageCrossModuleIsolation(t *testing.T) {
	c := rabbitCase()
	c.Affected = &domain.AffectedResult{
		SelectedModules: []string{"mod/amqp", "mod/other"},
	}
	c.Vulnerability.AffectedSymbols = []domain.SymbolRef{
		{Package: "mod/other/peer", Symbol: "handleFrame"}, // unexported, module B
	}
	// Product calls module A's API — nothing into mod/other.
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/amqp", Function: "DialTLS", Callee: "mod/amqp.DialTLS", ModuleOwner: "mod/amqp",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result == domain.ClaimTrue {
		t.Fatalf("got TRUE — module A usage must not prove module B subject: %s", claim.Explanation)
	}
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE candidate: no calls into the subject-owning module", claim.Result)
	}
}

// The positive side of the same attribution: a call into the subject's
// own module still proves the unexported sink runs.
func TestModuleUsageOwningModuleTrue(t *testing.T) {
	c := rabbitCase()
	c.Affected = &domain.AffectedResult{
		SelectedModules: []string{"mod/amqp", "mod/other"},
	}
	c.Vulnerability.AffectedSymbols = []domain.SymbolRef{
		{Package: "mod/other/peer", Symbol: "handleFrame"},
	}
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/other", Function: "main", Callee: "mod/other.Connect", ModuleOwner: "mod/other",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE: subject-owning module is used", claim.Result)
	}
}

// Nested modules: example.com/mod and example.com/mod/v2 share a path
// prefix — the subject's owner is the LONGEST matching module, or the
// parent's API usage bleeds into the child's verdict.
func TestModuleUsageNestedModuleIsolation(t *testing.T) {
	c := rabbitCase()
	c.Affected = &domain.AffectedResult{
		SelectedModules: []string{"mod/amqp", "mod/amqp/v2"},
	}
	c.Vulnerability.AffectedSymbols = []domain.SymbolRef{
		{Package: "mod/amqp/v2/peer", Symbol: "handleFrame"},
	}
	// Product calls the PARENT module's API — nothing into mod/amqp/v2.
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/amqp", Function: "DialTLS", Callee: "mod/amqp.DialTLS", ModuleOwner: "mod/amqp",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result == domain.ClaimTrue {
		t.Fatalf("got TRUE — parent module usage must not prove nested-module subject: %s", claim.Explanation)
	}
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE candidate: no calls into the owning module", claim.Result)
	}
}

// Same nesting, positive direction: a call into mod/amqp/v2 still proves
// the unexported sink runs — longest-match attribution is not a veto.
func TestModuleUsageNestedModuleTrue(t *testing.T) {
	c := rabbitCase()
	c.Affected = &domain.AffectedResult{
		SelectedModules: []string{"mod/amqp", "mod/amqp/v2"},
	}
	c.Vulnerability.AffectedSymbols = []domain.SymbolRef{
		{Package: "mod/amqp/v2/peer", Symbol: "handleFrame"},
	}
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/v2", Function: "main", Callee: "mod/amqp/v2.Connect", ModuleOwner: "mod/amqp/v2",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE: nested owning module is used", claim.Result)
	}
}

func TestModuleUsageNestedDependencyOutsideAdvisory(t *testing.T) {
	c := rabbitCase()
	c.Affected = &domain.AffectedResult{SelectedModules: []string{"mod/amqp"}}
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/v2", Function: "main", Callee: "mod/amqp/v2.Connect", ModuleOwner: "mod/amqp/v2",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN: nested dependency may call parent transitively", claim.Result)
	}
}

func TestModuleUsageUnknownOwnerBlocksAbsence(t *testing.T) {
	c := rabbitCase()
	c.EvidenceGraph.AddModuleUsages(domain.CallSite{
		Package: "prod/v2", Function: "main", Callee: "mod/amqp/v2.Connect",
	})
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID: "C-REACH", Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s, want UNKNOWN: module owner was not resolved", claim.Result)
	}
}

// A confirmed module's version must not decide a condition whose subject
// belongs to a pending (version-undecidable) module.
func TestVersionFactPendingModuleSubject(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.Affected = &domain.AffectedResult{
		VersionAffected: domain.ClaimTrue,
		ResolvedVersion: "v1.0.0",
		SelectedModule:  "mod/a",
		SelectedModules: []string{"mod/a", "mod/b"},
		PendingModules:  []string{"mod/b"},
		EvidenceIDs:     []domain.EvidenceID{"EV-AFFECTED-MODULES"},
	}
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-BUILD", Kind: domain.ConditionBuild,
		Description: "The version must be prior to 2.0 (the release containing the fix).",
		Subjects:    []domain.SymbolRef{{Package: "mod/b/lib", Symbol: "Open"}},
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s — module A's version must not prove a module-B condition", claim.Result)
	}
}

// Same version fact stays usable for subjects of the confirmed module.
func TestVersionFactConfirmedModuleSubject(t *testing.T) {
	c := &domain.AnalysisCase{}
	c.Affected = &domain.AffectedResult{
		VersionAffected: domain.ClaimTrue,
		ResolvedVersion: "v1.0.0",
		SelectedModule:  "mod/a",
		SelectedModules: []string{"mod/a", "mod/b"},
		PendingModules:  []string{"mod/b"},
		EvidenceIDs:     []domain.EvidenceID{"EV-AFFECTED-MODULES"},
	}
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-BUILD", Kind: domain.ConditionBuild,
		Description: "The version must be prior to 2.0 (the release containing the fix).",
		Subjects:    []domain.SymbolRef{{Package: "mod/a/lib", Symbol: "Open"}},
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE: subject owns the attributed module", claim.Result)
	}
}

func TestVersionFactSingularSubjectOtherModule(t *testing.T) {
	c := affectedCase("v1.0.0")
	c.Affected.SelectedModule = "mod/a"
	c.Affected.SelectedModules = []string{"mod/a", "mod/b"}
	c.Affected.PendingModules = []string{"mod/b"}
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-BUILD", Kind: domain.ConditionBuild,
		Description: "version must be prior to 2.0",
		Subject:     &domain.SymbolRef{Package: "mod/b/lib", Symbol: "Open"},
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s — singular subject belongs to pending module", claim.Result)
	}
}

func TestVersionFactUnboundMultiModule(t *testing.T) {
	c := affectedCase("v1.0.0")
	c.Affected.SelectedModule = "mod/a"
	c.Affected.SelectedModules = []string{"mod/a", "mod/b"}
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-BUILD", Kind: domain.ConditionBuild,
		Description: "version must be prior to 2.0",
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s — condition has no module attribution", claim.Result)
	}
}

func TestVersionFactStdlibSubjectOtherModule(t *testing.T) {
	c := affectedCase("v1.0.0")
	c.Affected.SelectedModule = "golang.org/x/sys"
	c.Affected.SelectedModules = []string{"golang.org/x/sys", "std"}
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-BUILD", Kind: domain.ConditionBuild,
		Description: "version must be prior to 2.0",
		Subject:     &domain.SymbolRef{Package: "syscall", Symbol: "Access"},
	}, c)
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("got %s — stdlib subject cannot inherit dependency version", claim.Result)
	}
}

func TestVersionFactStdlibSubjectSelectedModule(t *testing.T) {
	c := affectedCase("v1.0.0")
	c.Affected.SelectedModule = "std"
	c.Affected.SelectedModules = []string{"std", "golang.org/x/sys"}
	claim := VersionFact{}.Evaluate(domain.Condition{
		ID: "C-BUILD", Kind: domain.ConditionBuild,
		Description: "version must be prior to 2.0",
		Subject:     &domain.SymbolRef{Package: "syscall", Symbol: "Access"},
	}, c)
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("got %s, want TRUE: stdlib subject belongs to selected std module", claim.Result)
	}
}
