package rootcause

import (
	"context"
	"path/filepath"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/fix"
	"example.com/vuln-analyzer/internal/goanalysis"
)

func depVuln() domain.Vulnerability {
	return domain.Vulnerability{
		ID:     "GO-TEST-1",
		Module: "example.com/dep",
		AffectedPackages: []domain.AffectedPackage{
			{Path: "example.com/dep/vuln", Symbols: []string{"Parse"}},
		},
		AffectedSymbols: []domain.SymbolRef{
			{Package: "example.com/dep/vuln", Symbol: "Parse"},
		},
		References: []domain.Reference{
			{Type: "FIX", URL: "https://example.com/dep/commit/abc"},
		},
		FixedVersions: []string{"v1.0.1"},
	}
}

func TestResolveFromAdvisorySymbols(t *testing.T) {
	m, evs, err := Resolver{}.Resolve(context.Background(), &domain.AnalysisCase{}, depVuln())
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != domain.RootCauseResolved || len(m.RootCauses) != 1 {
		t.Fatalf("model=%+v", m)
	}
	if m.RootCauses[0].Symbol != "Parse" || m.RootCauses[0].Role != domain.RootCauseSink {
		t.Fatalf("rc=%+v", m.RootCauses[0])
	}
	if len(evs) == 0 {
		t.Fatal("expected advisory evidence")
	}
}

type fakePatch struct {
	out string
	err error
	got fix.Reference
}

func (f *fakePatch) Fetch(_ context.Context, ref fix.Reference) (string, error) {
	f.got = ref
	return f.out, f.err
}

func TestResolveFromPatch(t *testing.T) {
	v := depVuln()
	v.AffectedSymbols = nil // force patch path
	p := &fakePatch{out: `diff --git a/vuln/vuln.go b/vuln/vuln.go
index 1..2 100644
--- a/vuln/vuln.go
+++ b/vuln/vuln.go
@@ -5,3 +5,4 @@ func Parse(s string) (string, error) {
-	return s, nil
+	if s == "" { return "", errors.New("empty") }
+	return s, nil
`}
	r := Resolver{Patch: p}
	m, evs, err := r.Resolve(context.Background(), &domain.AnalysisCase{}, v)
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != domain.RootCauseResolved || len(m.RootCauses) != 1 {
		t.Fatalf("model=%+v", m)
	}
	rc := m.RootCauses[0]
	if rc.Symbol != "Parse" || rc.Package != "example.com/dep/vuln" {
		t.Fatalf("rc=%+v", rc)
	}
	var hasFix bool
	for _, e := range evs {
		if e.Kind == domain.EvidenceFixDiff {
			hasFix = true
		}
	}
	if !hasFix {
		t.Fatal("expected FIX_DIFF evidence")
	}
}

func TestResolveNotFound(t *testing.T) {
	m, _, err := Resolver{}.Resolve(context.Background(), &domain.AnalysisCase{}, domain.Vulnerability{ID: "X"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != domain.RootCauseNotFound {
		t.Fatalf("status=%s", m.Status)
	}
}

func TestVerifierDropsUnknown(t *testing.T) {
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	if err != nil {
		t.Fatal(err)
	}
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink},
			{Package: "example.com/dep/vuln", Symbol: "Nope", Role: domain.RootCauseSink},
		},
	}
	lim := vf.Verify(context.Background(), m, depVuln())
	if len(m.RootCauses) != 1 || m.RootCauses[0].Symbol != "Parse" {
		t.Fatalf("root causes=%+v lim=%v", m.RootCauses, lim)
	}
	if len(m.Alternatives) != 1 || m.Alternatives[0].Symbol != "Nope" {
		t.Fatalf("alternatives=%+v", m.Alternatives)
	}
	if len(m.Unverified) != 1 || m.Unverified[0].Symbol != "Nope" {
		t.Fatalf("unverified=%+v — in-scope candidate that failed resolution must be flagged", m.Unverified)
	}
}

// A candidate outside the advisory's affected packages is an alternative,
// not an unverified in-scope sink — it must not block the exploit model.
func TestVerifierOutOfScopeNotUnverified(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink},
			{Package: "example.com/dep/other", Symbol: "Fn", Role: domain.RootCauseSink},
		},
	}
	vf.Verify(context.Background(), m, depVuln())
	if len(m.Unverified) != 0 {
		t.Fatalf("unverified=%+v — out-of-scope drop is not a verification failure", m.Unverified)
	}
}

func TestVerifierRejectsForeignPackage(t *testing.T) {
	abs, _ := filepath.Abs(filepath.Join("..", "..", "testdata", "constprod"))
	vf := Verifier{Source: &goanalysis.Index{Dir: abs}}
	v := depVuln()
	m := &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{
			{Package: "example.com/dep/other", Symbol: "Fn", Role: domain.RootCauseSink},
		},
	}
	vf.Verify(context.Background(), m, v)
	if m.Status != domain.RootCauseAmbiguous {
		t.Fatalf("status=%s want AMBIGUOUS (all candidates rejected)", m.Status)
	}
}
