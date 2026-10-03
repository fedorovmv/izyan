package goanalysis

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

var locusTestCond = domain.Condition{
	ID:        "C-LOCUS",
	Kind:      domain.ConditionSymbolReachable,
	Mandatory: true,
	Params:    map[string]string{domain.ParamCheck: domain.CheckLocus},
	Subjects: []domain.SymbolRef{
		{Package: "example.com/lib/internal/xds/server", Symbol: "RouteAndProcess"},
	},
}

func locusTestCase(paths ...string) *domain.AnalysisCase {
	c := &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{}}
	content := ""
	for _, p := range paths {
		content += `{"ImportPath":"` + p + `"}`
	}
	c.EvidenceGraph.Evidence = append(c.EvidenceGraph.Evidence, domain.Evidence{
		ID: "EV-PKGS", Kind: domain.EvidencePackageList, Content: content,
	})
	return c
}

func locusFalseClaim() domain.Claim {
	return domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusPackageAbsent,
	}
}

// All locus packages absent from the build graph verifies the falsifier —
// without a source index configured.
func TestVerifyLocusAbsentVerified(t *testing.T) {
	c := locusTestCase("example.com/prod", "example.com/lib/internal/transport")
	out := (Verifier{}).VerifyFalse(context.Background(), c, locusFalseClaim(), locusTestCond)
	if out.NegativeVerification == nil ||
		out.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("nv=%+v", out.NegativeVerification)
	}
}

// A locus package present in the graph contradicts the FALSE — the defect
// code is linked, so package absence does not hold.
func TestVerifyLocusAbsentContradicted(t *testing.T) {
	c := locusTestCase("example.com/lib/internal/xds/server")
	out := (Verifier{}).VerifyFalse(context.Background(), c, locusFalseClaim(), locusTestCond)
	if out.NegativeVerification == nil ||
		out.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("nv=%+v", out.NegativeVerification)
	}
}

// Missing package-list evidence leaves the falsifier unverified — a loading
// failure is never absence.
func TestVerifyLocusAbsentNoEvidence(t *testing.T) {
	c := &domain.AnalysisCase{EvidenceGraph: domain.EvidenceGraph{}}
	out := (Verifier{}).VerifyFalse(context.Background(), c, locusFalseClaim(), locusTestCond)
	if out.NegativeVerification == nil ||
		out.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v", out.NegativeVerification)
	}
}

func TestVerifyLocusFunctionUnreached(t *testing.T) {
	ix := &Index{
		Dir: t.TempDir(),
	}
	v := Verifier{Source: ix}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc/internal/xds/server", Symbol: "RouteAndProcess"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("expected NegativeVerified, got %+v", verified.NegativeVerification)
	}
}

func TestVerifyLocusFunctionUnreached_ContradictedByCallPath(t *testing.T) {
	v := Verifier{}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc/internal/xds/server", Symbol: "RouteAndProcess"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			CallPaths: []domain.CallPath{
				{
					Frames: []domain.CallSite{
						{Package: "example.com/app", Function: "main"},
						{Package: "google.golang.org/grpc/internal/xds/server", Function: "RouteAndProcess"},
					},
				},
			},
		},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("expected NegativeContradicted, got %+v", verified.NegativeVerification)
	}
	if verified.Result != domain.ClaimUnknown {
		t.Fatalf("expected ClaimUnknown after contradiction, got %s", verified.Result)
	}
}

func TestVerifyLocusFunctionUnreached_ContradictedByModuleReachable(t *testing.T) {
	v := Verifier{}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc/internal/xds/server", Symbol: "RouteAndProcess"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			ModuleReachable: map[string][]string{
				"google.golang.org/grpc/internal/xds/server.RouteAndProcess": {"Entry", "RouteAndProcess"},
			},
		},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("expected NegativeContradicted, got %+v", verified.NegativeVerification)
	}
	if verified.Result != domain.ClaimUnknown {
		t.Fatalf("expected ClaimUnknown after contradiction, got %s", verified.Result)
	}
}

func TestVerifyLocusFunctionUnreached_ContradictedByModuleUsage(t *testing.T) {
	v := Verifier{}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc/internal/xds/server", Symbol: "RouteAndProcess"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{
			ModuleUsages: []domain.CallSite{
				{
					Callee: "google.golang.org/grpc/internal/xds/server.RouteAndProcess",
					File:   "main.go",
					Line:   42,
				},
			},
		},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("expected NegativeContradicted, got %+v", verified.NegativeVerification)
	}
}

func TestVerifyLocusFunctionUnreached_ContradictedByDirectImport(t *testing.T) {
	dir := t.TempDir()
	src := `package main
import _ "google.golang.org/grpc/internal/xds/server"
func main() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	ix := &Index{Dir: dir}
	v := Verifier{Source: ix}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc/internal/xds/server", Symbol: "RouteAndProcess"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("expected NegativeContradicted, got %+v", verified.NegativeVerification)
	}
}

func TestVerifyLocusFunctionUnreached_ContradictedByLinkname(t *testing.T) {
	dir := t.TempDir()
	src := `package main
//go:linkname customRoute google.golang.org/grpc/internal/xds/server.RouteAndProcess
func customRoute()
func main() {}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0644); err != nil {
		t.Fatal(err)
	}

	ix := &Index{Dir: dir}
	v := Verifier{Source: ix}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc/internal/xds/server", Symbol: "RouteAndProcess"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("expected NegativeContradicted, got %+v", verified.NegativeVerification)
	}
}

func TestVerifyLocusFunctionUnreached_NoSubjects(t *testing.T) {
	v := Verifier{}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("expected NegativeInsufficientScope, got %+v", verified.NegativeVerification)
	}
}

func TestVerifyLocusFunctionUnreached_NonInternalNoSource(t *testing.T) {
	v := Verifier{} // no source index
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "google.golang.org/grpc/xds", Symbol: "PublicFunc"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("expected NegativeInsufficientScope, got %+v", verified.NegativeVerification)
	}
}

func TestVerifyLocusFunctionUnreached_MethodInInterface(t *testing.T) {
	ix := &Index{
		Dir: t.TempDir(),
	}
	v := Verifier{Source: ix}
	claim := domain.Claim{
		ID:          "CL-C-LOCUS",
		ConditionID: "C-LOCUS",
		Result:      domain.ClaimFalse,
		Falsifier:   domain.FalsifierLocusFunctionUnreached,
	}
	// "Close" is a standard library interface method (io.Closer).
	cond := domain.Condition{
		ID: "C-LOCUS",
		Subjects: []domain.SymbolRef{
			{Package: "example.com/dep/internal/pkg", Symbol: "MyStruct.Close"},
		},
	}
	c := &domain.AnalysisCase{
		EvidenceGraph: domain.EvidenceGraph{},
	}
	verified := v.VerifyFalse(context.Background(), c, claim, cond)
	if verified.NegativeVerification == nil || verified.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("expected NegativeInsufficientScope for interface method, got %+v", verified.NegativeVerification)
	}
}
