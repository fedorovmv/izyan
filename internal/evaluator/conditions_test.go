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
	claim := SymbolReachable{}.Evaluate(domain.Condition{
		ID:   "C-REACH",
		Kind: domain.ConditionSymbolReachable,
	}, c)
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("got %s, want FALSE candidate", claim.Result)
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
