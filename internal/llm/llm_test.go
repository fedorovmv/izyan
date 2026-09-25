package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func mockServer(t *testing.T, reply string) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := chatResponse{Choices: []struct {
			Message chatMessage `json:"message"`
		}{{Message: chatMessage{Role: "assistant", Content: reply}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	cfg := Config{BaseURL: srv.URL, AnalyzeModel: "m", BuildModel: "m", Enabled: true}
	return NewClient(cfg), srv
}

func newCase() *domain.AnalysisCase {
	return &domain.AnalysisCase{}
}

func TestRootCauseResolverFallsBackToLLM(t *testing.T) {
	reply := `[{"package":"example.com/dep","symbol":"vuln.Parse","mechanism":"xml parse"}]`
	client, srv := mockServer(t, reply)
	defer srv.Close()

	fb := stubResolver{model: &domain.RootCauseModel{Status: domain.RootCauseNotFound}}
	r := RootCauseResolver{Client: client, Fallback: fb}
	c := newCase()
	m, _, err := r.Resolve(context.Background(), c, domain.Vulnerability{ID: "X"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Status != domain.RootCauseResolved || len(m.RootCauses) != 1 {
		t.Fatalf("model=%+v", m)
	}
	if m.RootCauses[0].Symbol != "vuln.Parse" {
		t.Fatalf("symbol=%s", m.RootCauses[0].Symbol)
	}
	if c.Workflow.Usage.LLMCalls != 1 {
		t.Fatalf("llm calls=%d", c.Workflow.Usage.LLMCalls)
	}
}

func TestRootCauseResolverKeepsDeterministicResult(t *testing.T) {
	client, srv := mockServer(t, "[]")
	defer srv.Close()
	fb := stubResolver{model: &domain.RootCauseModel{
		Status:     domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S"}},
	}}
	r := RootCauseResolver{Client: client, Fallback: fb}
	c := newCase()
	m, _, _ := r.Resolve(context.Background(), c, domain.Vulnerability{})
	if len(m.RootCauses) != 1 || m.RootCauses[0].Symbol != "S" {
		t.Fatalf("model=%+v", m)
	}
	if c.Workflow.Usage.LLMCalls != 0 {
		t.Fatal("llm must not run when deterministic resolves")
	}
}

func TestRootCauseResolverUnparseableKeepsNotFound(t *testing.T) {
	client, srv := mockServer(t, "not json at all")
	defer srv.Close()
	r := RootCauseResolver{Client: client, Fallback: stubResolver{
		model: &domain.RootCauseModel{Status: domain.RootCauseNotFound},
	}}
	c := newCase()
	m, _, _ := r.Resolve(context.Background(), c, domain.Vulnerability{})
	if m.Status == domain.RootCauseResolved || len(m.RootCauses) > 0 {
		t.Fatalf("model=%+v", m)
	}
}

func TestExploitModelBuilderValidatesAndMerges(t *testing.T) {
	reply := `{"impact":"xss","mandatory_conditions":[{"id":"C-LLM","kind":"VALIDATION","description":"needs escaping","subjects":[{"package":"p","symbol":"S"}]}]}`
	client, srv := mockServer(t, reply)
	defer srv.Close()

	fb := stubBuilder{model: &domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH", Kind: domain.ConditionSymbolReachable}},
	}}
	b := ExploitModelBuilder{Client: client, Fallback: fb}
	c := newCase()
	rc := &domain.RootCauseModel{Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S", Role: domain.RootCauseSink}}}
	m, lims := b.Build(context.Background(), c, domain.Vulnerability{Summary: "x"}, rc)
	if m == nil || len(m.MandatoryConditions) != 2 {
		t.Fatalf("model=%+v lims=%v", m, lims)
	}
}

func TestExploitModelBuilderRejectsNonSinkSubject(t *testing.T) {
	reply := `{"mandatory_conditions":[{"id":"C-X","kind":"SYMBOL_REACHABLE","subjects":[{"package":"evil","symbol":"F"}]}]}`
	client, srv := mockServer(t, reply)
	defer srv.Close()
	fb := stubBuilder{model: &domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH"}},
	}}
	b := ExploitModelBuilder{Client: client, Fallback: fb}
	c := newCase()
	rc := &domain.RootCauseModel{Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S", Role: domain.RootCauseSink}}}
	m, lims := b.Build(context.Background(), c, domain.Vulnerability{}, rc)
	if len(m.MandatoryConditions) != 1 {
		t.Fatalf("model=%+v", m)
	}
	joined := ""
	for _, l := range lims {
		joined += l
	}
	if joined == "" {
		t.Fatal("rejection must surface as limitation")
	}
}

func TestLLMReviewerParsesRevise(t *testing.T) {
	reply := `{"result":"REVISE","findings":[{"target_type":"claim","target_id":"CL-1","problem":"unsupported","severity":"high"}]}`
	client, srv := mockServer(t, reply)
	defer srv.Close()
	rv := Reviewer{Client: client}
	c := newCase()
	r := rv.Review(c, domain.VerdictResult{Verdict: domain.VerdictExploitable})
	if r.Result != domain.ReviewRevise || len(r.Findings) != 1 {
		t.Fatalf("review=%+v", r)
	}
}

func TestExtractJSON(t *testing.T) {
	cases := map[string]string{
		"```json\n{\"a\":1}\n```": `{"a":1}`,
		"prefix {\"a\":2} suffix": `{"a":2}`,
		"[1,2]":                   "[1,2]",
		"no json":                 "",
	}
	for in, want := range cases {
		if got := ExtractJSON(in); got != want {
			t.Fatalf("ExtractJSON(%q)=%q want %q", in, got, want)
		}
	}
}

type stubResolver struct {
	model *domain.RootCauseModel
	evs   []domain.Evidence
	err   error
}

func (s stubResolver) Resolve(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error) {
	return s.model, s.evs, s.err
}

type stubBuilder struct {
	model *domain.ExploitModel
	lims  []string
}

func (s stubBuilder) Build(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability, _ *domain.RootCauseModel) (*domain.ExploitModel, []string) {
	return s.model, s.lims
}
