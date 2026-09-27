package evaluator

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func platformCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{Product: domain.ProductSnapshot{
		GOOS: "linux", GOARCH: "amd64",
		ReleaseGoVersion: "go1.21.5",
	}}
}

func TestPlatformEvaluate(t *testing.T) {
	ev := Platform{}
	c := platformCase()

	mk := func(params map[string]string) domain.Condition {
		return domain.Condition{ID: "C-PLAT", Kind: domain.ConditionPlatform, Params: params}
	}

	// Match on all declared facts -> TRUE.
	cl := ev.Evaluate(mk(map[string]string{"goos": "linux", "go_version": "<1.22"}), c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("match => TRUE, got %s (%s)", cl.Result, cl.Explanation)
	}
	// GOOS mismatch -> FALSE.
	cl = ev.Evaluate(mk(map[string]string{"goos": "windows"}), c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("mismatch => FALSE, got %s", cl.Result)
	}
	// go_version bound violated -> FALSE.
	cl = ev.Evaluate(mk(map[string]string{"go_version": ">=1.24"}), c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("violated bound => FALSE, got %s (%s)", cl.Result, cl.Explanation)
	}
	// Missing snapshot fact -> UNKNOWN.
	c2 := platformCase()
	c2.Product.GOOS = ""
	cl = ev.Evaluate(mk(map[string]string{"goos": "linux"}), c2)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("missing fact => UNKNOWN, got %s", cl.Result)
	}
	// No evaluable params -> UNKNOWN with limitation.
	cl = ev.Evaluate(mk(nil), c)
	if cl.Result != domain.ClaimUnknown || len(cl.Limitations) == 0 {
		t.Fatalf("no params => UNKNOWN+limitation, got %+v", cl)
	}
}
