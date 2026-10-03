package evaluator

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func i64(v int64) *int64 { return &v }

func TestParseBoundDisjuncts(t *testing.T) {
	terms, leftovers := parseBound("prefetchCount < 0 or prefetchSize < 0")
	if len(leftovers) > 0 || len(terms) != 2 {
		t.Fatalf("terms=%+v leftovers=%v", terms, leftovers)
	}
	if terms[0].arg != 0 || terms[1].arg != 1 {
		t.Fatalf("positional binding wrong: %+v", terms)
	}
	if !terms[0].satisfies(-1) || terms[0].satisfies(0) {
		t.Fatalf("< 0 satisfaction wrong")
	}
}

func TestParseBoundLeftovers(t *testing.T) {
	_, leftovers := parseBound("x > INT32_MAX")
	if len(leftovers) != 0 {
		// INT32_MAX is a valid right side syntactically — symbolic, hasVal=false
		t.Fatalf("unexpected leftovers %v", leftovers)
	}
	terms, _ := parseBound("x > INT32_MAX")
	if terms[0].hasVal {
		t.Fatalf("symbolic bound must not resolve: %+v", terms[0])
	}
	_, leftovers = parseBound("len(x) < 0")
	if len(leftovers) != 1 {
		t.Fatalf("unparseable term must be a leftover: %v", leftovers)
	}
}

func TestBoundTermFalsifiedBy(t *testing.T) {
	neg := boundTerm{name: "x", op: "<", val: 0, hasVal: true}
	if !neg.falsifiedBy(i64(0), i64(1024)) {
		t.Fatal("[0,1024] falsifies x<0")
	}
	if neg.falsifiedBy(i64(-5), nil) {
		t.Fatal("[-5,∞) does not falsify x<0")
	}
	if neg.falsifiedBy(nil, i64(10)) {
		t.Fatal("(−∞,10] does not falsify x<0")
	}
	upper := boundTerm{name: "x", op: ">", val: 10, hasVal: true}
	if !upper.falsifiedBy(i64(0), i64(10)) {
		t.Fatal("[0,10] falsifies x>10")
	}
	if upper.falsifiedBy(nil, i64(100)) {
		t.Fatal("(−∞,100] does not falsify x>10")
	}
}

func TestVerifyBoundFalsified(t *testing.T) {
	c := &domain.AnalysisCase{}
	sink := domain.CallSite{File: "r.go", Line: 50}
	c.EvidenceGraph.Validations = []domain.Validation{
		{Guard: true, Arg: 0,
			Covers: &sink, BoundLow: i64(0), BoundHigh: i64(1024),
			Property: "field-write prefetchCount"},
		{Guard: true, Arg: 1,
			Covers: &sink, BoundLow: i64(0), BoundHigh: i64(1024),
			Property: "field-write prefetchSize"},
	}
	cond := domain.Condition{
		Kind: domain.ConditionInputConstraint,
		Params: map[string]string{
			domain.ParamBound: "prefetchCount < 0 or prefetchSize < 0",
		},
	}
	flows := []domain.DataFlow{
		{Arg: 0, Sink: sink, Origin: domain.OriginConfiguration},
		{Arg: 1, Sink: sink, Origin: domain.OriginConfiguration},
		{Arg: 2, Sink: sink, Origin: domain.OriginConstant},
	}
	note := verifyBound(cond, c, flows)
	if !strings.HasPrefix(note, "bound verified") {
		t.Fatalf("expected verified bound, got %q", note)
	}
}

func TestVerifyBoundInsufficientRange(t *testing.T) {
	c := &domain.AnalysisCase{}
	sink := domain.CallSite{File: "r.go", Line: 50}
	// One-sided guard cannot falsify x<0.
	c.EvidenceGraph.Validations = []domain.Validation{
		{Guard: true, Arg: 0,
			Covers: &sink, BoundHigh: i64(1024)},
	}
	cond := domain.Condition{
		Kind:   domain.ConditionInputConstraint,
		Params: map[string]string{domain.ParamBound: "x < 0"},
	}
	flows := []domain.DataFlow{
		{Arg: 0, Sink: sink, Origin: domain.OriginConfiguration},
	}
	note := verifyBound(cond, c, flows)
	if strings.HasPrefix(note, "bound verified") {
		t.Fatalf("one-sided range must not verify x<0: %q", note)
	}
	if !strings.Contains(note, "not fully falsified") {
		t.Fatalf("expected falsification gap, got %q", note)
	}
}

func TestConstViolatesBound(t *testing.T) {
	sink := domain.CallSite{File: "r.go", Line: 50}
	cond := domain.Condition{
		Kind:   domain.ConditionInputConstraint,
		Params: map[string]string{domain.ParamBound: "prefetchCount < 0 or prefetchSize < 0"},
	}
	violating := []domain.DataFlow{
		{Arg: 0, Sink: sink, Origin: domain.OriginConstant, Value: i64(-5)},
	}
	if hit := constViolatesBound(cond, violating); hit == "" {
		t.Fatal("constant -5 at arg0 must satisfy prefetchCount < 0")
	}
	safe := []domain.DataFlow{
		{Arg: 0, Sink: sink, Origin: domain.OriginConstant, Value: i64(10)},
	}
	if hit := constViolatesBound(cond, safe); hit != "" {
		t.Fatalf("constant 10 must not violate: %s", hit)
	}
}
