package eval_test

import (
	"encoding/json"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/eval"
)

func record(r *eval.Report, c eval.Case, verdict domain.Verdict) {
	r.Record(c, verdict, "", nil, nil)
}

func TestReportFalseSafe(t *testing.T) {
	var r eval.Report
	// Exploitable expectation, analyzer says NO_EXPLOIT_PATH_FOUND.
	record(&r, eval.Case{ID: "c1", Vuln: "V-1", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictNoExploitPathFound)
	if r.Metrics.FalseSafe != 1 {
		t.Fatalf("false_safe=%d want 1", r.Metrics.FalseSafe)
	}
	if !r.Results[0].FalseSafe {
		t.Fatal("result not flagged false-safe")
	}

	// Safe expectation met by a safe verdict — not false-safe.
	record(&r, eval.Case{ID: "c2", Vuln: "V-2", Expect: []string{"NO_EXPLOIT_PATH_FOUND"}},
		domain.VerdictNoExploitPathFound)
	if r.Metrics.FalseSafe != 1 {
		t.Fatalf("false_safe=%d want still 1", r.Metrics.FalseSafe)
	}

	// INCONCLUSIVE where EXPLOITABLE expected: a fail but not false-safe.
	record(&r, eval.Case{ID: "c3", Vuln: "V-3", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictInconclusive)
	if r.Metrics.FalseSafe != 1 {
		t.Fatalf("false_safe=%d want still 1", r.Metrics.FalseSafe)
	}
	if r.Metrics.ExpectPass != 1 || r.Metrics.ExpectFail != 2 || r.Metrics.Total != 3 {
		t.Fatalf("metrics=%+v", r.Metrics)
	}
}

func TestReportInconclusiveCounted(t *testing.T) {
	var r eval.Report
	record(&r, eval.Case{Vuln: "V-1", Expect: []string{"INCONCLUSIVE"}}, domain.VerdictInconclusive)
	record(&r, eval.Case{Vuln: "V-2"}, domain.VerdictInconclusive)
	if r.Metrics.Inconclusive != 2 {
		t.Fatalf("inconclusive=%d", r.Metrics.Inconclusive)
	}
	if r.Metrics.NoExpect != 1 {
		t.Fatalf("informational=%d", r.Metrics.NoExpect)
	}
}

func TestReportSignalClearedCountsOnlySafeVerdictsAgainstGovulncheckSignals(t *testing.T) {
	var r eval.Report
	for _, tc := range []struct {
		id       string
		verdict  domain.Verdict
		baseline string
		expect   []string
	}{
		{"negative", domain.VerdictNoExploitPathFound, eval.BaselinePackageLevel, []string{"NO_EXPLOIT_PATH_FOUND"}},
		{"positive", domain.VerdictExploitable, eval.BaselineReachable, []string{"EXPLOITABLE"}},
		{"silent", domain.VerdictNotAffected, eval.BaselineSilent, []string{"NOT_AFFECTED"}},
		{"unsafe", domain.VerdictNoExploitPathFound, eval.BaselineReachable, []string{"EXPLOITABLE"}},
	} {
		r.Record(eval.Case{ID: tc.id, Expect: tc.expect}, tc.verdict, "", nil, nil)
		r.RecordBaseline(tc.baseline)
	}
	if r.Metrics.GovulncheckSignals != 3 || r.Metrics.SignalCleared != 1 {
		t.Fatalf("signal metrics=%+v; want 1/3", r.Metrics)
	}
	if r.Metrics.ReachableSignals != 2 || r.Metrics.ReachableCleared != 0 ||
		r.Metrics.PackageLevelSignals != 1 || r.Metrics.PackageLevelCleared != 1 {
		t.Fatalf("signal breakdown=%+v; want reachable 0/2 and package-level 1/1", r.Metrics)
	}
}

func TestReportClaimsAssert(t *testing.T) {
	var r eval.Report
	r.Record(eval.Case{
		Vuln:   "V-1",
		Expect: []string{"EXPLOITABLE"},
		Claims: map[string]string{"C-REACH": "TRUE", "C-INPUT": "TRUE"},
	}, domain.VerdictExploitable, "", map[string]string{
		"C-REACH": "TRUE", "C-INPUT": "TRUE",
	}, nil)
	if r.Metrics.ClaimsFail != 0 {
		t.Fatalf("claims_fail=%d want 0", r.Metrics.ClaimsFail)
	}
	r.Record(eval.Case{
		Vuln:   "V-2",
		Claims: map[string]string{"C-EXPOSED": "FALSE"},
	}, domain.VerdictNoExploitPathFound, "", map[string]string{
		"C-EXPOSED": "TRUE",
	}, nil)
	if r.Metrics.ClaimsFail != 1 {
		t.Fatalf("claims_fail=%d want 1", r.Metrics.ClaimsFail)
	}
}

func TestCaseUnmarshalRootCauses(t *testing.T) {
	raw := `{"cases":[{
		"vuln":"GO-X","repo":"testdata/ifaceprod",
		"root_causes":[
			"example.com/dep/vuln.Parse",
			{"package":"example.com/dep/vuln","symbol":"URI.String","role":"SINK"}
		],
		"expect":["INCONCLUSIVE"],
		"expect_claims":{"C-ROUNDTRIP":"FALSE"}
	}]}`
	var c eval.Corpus
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	rc := c.Cases[0].RootCauses
	if len(rc) != 2 {
		t.Fatalf("root_causes=%+v", rc)
	}
	if rc[0].Package != "example.com/dep/vuln" || rc[0].Symbol != "Parse" {
		t.Fatalf("string form parsed wrong: %+v", rc[0].RootCause)
	}
	if rc[1].Symbol != "URI.String" || rc[1].Package != "example.com/dep/vuln" {
		t.Fatalf("object form parsed wrong: %+v", rc[1].RootCause)
	}
	if rc[0].Role != domain.RootCauseSink {
		t.Fatalf("role=%q want SINK", rc[0].Role)
	}
}

func TestMarkdownRenders(t *testing.T) {
	var r eval.Report
	record(&r, eval.Case{ID: "c1", Vuln: "V-1", Expect: []string{"EXPLOITABLE"}},
		domain.VerdictNoExploitPathFound)
	md := r.Markdown()
	if !strings.Contains(md, "false-safe: 1") || !strings.Contains(md, "FALSE-SAFE") {
		t.Fatalf("markdown missing false-safe markers:\n%s", md)
	}
}
