package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/goanalysis"
)

func mockServer(t *testing.T, reply string) (*Client, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		resp := chatResponse{Choices: []struct {
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
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
	r := &RootCauseResolver{Client: client, Fallback: fb}
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
	r := &RootCauseResolver{Client: client, Fallback: fb}
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
	r := &RootCauseResolver{Client: client, Fallback: stubResolver{
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

// scriptServer returns queued responses in order, then repeats the last.
func scriptServer(t *testing.T, replies ...string) (*Client, *httptest.Server, *int) {
	t.Helper()
	var n int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i := n
		if i >= len(replies) {
			i = len(replies) - 1
		}
		n++
		resp := chatResponse{Choices: []struct {
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{{Message: chatMessage{Role: "assistant", Content: replies[i]}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	return NewClient(Config{BaseURL: srv.URL, AnalyzeModel: "m", Enabled: true}), srv, &n
}

func TestAgentResolvesClaimWithTools(t *testing.T) {
	// Step 1: tool call to trace_argument; step 2: claim TRUE citing evidence.
	client, srv, calls := scriptServer(t,
		`{"tool_calls":[{"name":"find_callers","args":{"package":"example.com/dep","symbol":"vuln.Parse"},"purpose":"locate sinks"}]}`,
		`{"claim":{"result":"TRUE","evidence_ids":["EV-001"],"explanation":"arg flows from os.Args"}}`)
	defer srv.Close()

	ix := &goanalysis.Index{Dir: filepath.Join("..", "..", "testdata", "constprod")}
	ev := ClaimEvaluator{Client: client, Tools: Tools{Source: ix}, MaxSteps: 4}
	c := newCase()
	cond := domain.Condition{ID: "C-IN", Kind: domain.ConditionInputConstraint,
		Subjects: []domain.SymbolRef{{Package: "example.com/dep", Symbol: "vuln.Parse"}}}
	cl := ev.Evaluate(cond, c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("claim=%+v", cl)
	}
	if len(cl.EvidenceIDs) == 0 {
		t.Fatal("claim must cite evidence")
	}
	if *calls != 2 {
		t.Fatalf("calls=%d", *calls)
	}
}

func TestAgentKeepsUnknownWithoutEvidence(t *testing.T) {
	client, srv, _ := scriptServer(t,
		`{"claim":{"result":"TRUE","evidence_ids":["EV-999"],"explanation":"made up"}}`)
	defer srv.Close()
	ix := &goanalysis.Index{Dir: filepath.Join("..", "..", "testdata", "constprod")}
	ev := ClaimEvaluator{Client: client, Tools: Tools{Source: ix}}
	cl := ev.Evaluate(domain.Condition{ID: "C-X", Kind: domain.ConditionCustom}, newCase())
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("unsupported TRUE must not survive: %+v", cl)
	}
}

func TestAgentStopsAtStepBudget(t *testing.T) {
	client, srv, calls := scriptServer(t, `{"tool_calls":[{"name":"find_entrypoints","args":{},"purpose":"x"}]}`)
	defer srv.Close()
	ix := &goanalysis.Index{Dir: filepath.Join("..", "..", "testdata", "constprod")}
	ev := ClaimEvaluator{Client: client, Tools: Tools{Source: ix}, MaxSteps: 2}
	cl := ev.Evaluate(domain.Condition{ID: "C-X", Kind: domain.ConditionCustom}, newCase())
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("claim=%+v", cl)
	}
	if *calls != 2 {
		t.Fatalf("calls=%d want 2", *calls)
	}
}

func TestBuildRetriesOnBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req chatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		reply := "garbage"
		if req.Messages[1].Content != "" && req.Model == "m" {
			// second call returns valid JSON
			if len(req.Messages) > 0 && req.Messages[0].Role == "system" {
				// distinguish attempts via call count is hard here; use a flag
			}
		}
		resp := chatResponse{Choices: []struct {
			Message      chatMessage `json:"message"`
			FinishReason string      `json:"finish_reason"`
		}{{Message: chatMessage{Role: "assistant", Content: reply}}}}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()
	client := NewClient(Config{BaseURL: srv.URL, BuildModel: "m", AnalyzeModel: "m", Enabled: true, BuildMaxRetries: 2})
	r := &RootCauseResolver{Client: client, Fallback: stubResolver{model: &domain.RootCauseModel{Status: domain.RootCauseNotFound}}}
	c := newCase()
	m, _, _ := r.Resolve(context.Background(), c, domain.Vulnerability{ID: "X"})
	if len(m.RootCauses) != 0 {
		t.Fatalf("model=%+v", m)
	}
	if c.Workflow.Usage.LLMCalls != 3 { // 1 + 2 retries
		t.Fatalf("llm calls=%d want 3", c.Workflow.Usage.LLMCalls)
	}
}

func TestDescribeBadOutput(t *testing.T) {
	cases := []struct {
		name    string
		content string
		finish  string
		want    string
	}{
		{"gemini refusal text", `his request was blocked by Gemini's filters. They can occasionally trigger by mistake on safe coding, security, or biology-related queries.`, "", "provider refusal"},
		{"finish content_filter", "", "content_filter", "provider refusal (finish_reason=content_filter)"},
		{"finish safety", "partial", "safety", "provider refusal (finish_reason=safety)"},
		{"empty stop", "   ", "stop", "empty output"},
		{"empty max", "", "length", "empty output (finish_reason=length)"},
		{"truncated json", `{"a": 1, "b":`, "length", "truncated output"},
		{"prose", "I would suggest looking at the code paths.", "stop", "non-JSON output"},
		{"generic refusal", "I'm sorry, but I cannot help with exploit code.", "", "provider refusal"},
	}
	for _, tc := range cases {
		got := DescribeBadOutput(tc.content, tc.finish)
		if !strings.HasPrefix(got, tc.want) {
			t.Errorf("%s: got %q want prefix %q", tc.name, got, tc.want)
		}
	}
	// snippet carries raw text for diagnosis, bounded
	d := DescribeBadOutput(strings.Repeat("x", 300), "")
	if !strings.Contains(d, "non-JSON output: ") || len(d) > 200 {
		t.Errorf("snippet unbounded or missing: %q…", d[:60])
	}
}

func TestStrictLLMExploitBuilderFailFast(t *testing.T) {
	// Refusal reply
	reply := `This request was blocked by Gemini's filters.`
	client, srv := mockServer(t, reply)
	defer srv.Close()

	fb := stubBuilder{model: &domain.ExploitModel{
		MandatoryConditions: []domain.Condition{{ID: "C-REACH"}},
	}}
	b := ExploitModelBuilder{Client: client, Fallback: fb}
	c := newCase()
	c.StrictLLM = true
	rc := &domain.RootCauseModel{
		Status:     domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{Package: "p", Symbol: "S", Role: domain.RootCauseSink}},
	}
	m, lims := b.Build(context.Background(), c, domain.Vulnerability{}, rc)
	if m != nil {
		t.Fatalf("expected nil model under StrictLLM, got %+v", m)
	}
	joined := strings.Join(lims, " ")
	if !strings.Contains(joined, "strict-llm:") {
		t.Fatalf("expected strict-llm limitation, got %v", lims)
	}
}

func TestStrictLLMReviewerFailFast(t *testing.T) {
	reply := `This request was blocked by Gemini's filters.`
	client, srv := mockServer(t, reply)
	defer srv.Close()

	rv := Reviewer{Client: client}
	c := newCase()
	c.StrictLLM = true
	r := rv.Review(c, domain.VerdictResult{Verdict: domain.VerdictExploitable})
	if r.Result != domain.ReviewRevise {
		t.Fatalf("expected ReviewRevise under StrictLLM refusal, got %v", r.Result)
	}
	found := false
	for _, f := range r.Findings {
		if strings.HasPrefix(f.Problem, "strict-llm:") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected finding with strict-llm: prefix, got %+v", r.Findings)
	}
}
