package eval_test

import (
	"context"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/eval"
)

type baselineRunner struct{ raw string }

func (r baselineRunner) RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, error) {
	return []byte(r.raw), nil
}

func TestBaselineSeparatesModulePackageAndReachableFindings(t *testing.T) {
	for _, tc := range []struct {
		name, raw, want string
	}{
		{"module only", `{"finding":{"osv":"V-1","trace":[{"module":"example.com/dep"}]}}`, "module-level"},
		{"package imported", `{"finding":{"osv":"V-1","trace":[{"module":"example.com/dep","package":"example.com/dep/vuln"}]}}`, eval.BaselinePackageLevel},
		{"symbol reachable", `{"finding":{"osv":"V-1","trace":[{"module":"example.com/dep","package":"example.com/dep/vuln","function":"Sink"}]}}`, eval.BaselineReachable},
		{"package after module", `{"finding":{"osv":"V-1","trace":[{"module":"example.com/dep"}]}}
{"finding":{"osv":"V-1","trace":[{"package":"example.com/dep/vuln"}]}}`, eval.BaselinePackageLevel},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := eval.Baseline(context.Background(), baselineRunner{tc.raw}, "", domain.Vulnerability{ID: "V-1"}, domain.ProductSnapshot{})
			if got != tc.want {
				t.Fatalf("baseline=%q want %q", got, tc.want)
			}
		})
	}
}
