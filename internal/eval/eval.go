// Package eval runs the analyzer over a corpus of cases and reports the
// spec's quality metrics — most importantly the false-safe count: cases
// where the analyzer returned a safe verdict (NOT_AFFECTED /
// NO_EXPLOIT_PATH_FOUND) while the expectation says it should not.
// That is the stop criterion of the project: a regression that makes an
// exploitable input look safe is the one failure the harness must catch.
package eval

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Case is one corpus entry: an advisory analyzed against a repository.
type Case struct {
	ID       string `json:"id,omitempty"`
	Vuln     string `json:"vuln"`
	VulnFile string `json:"vuln_file,omitempty"`
	Repo     string `json:"repo,omitempty"`
	// RootCauses supplies manual root causes, bypassing resolution. Entries
	// are either "pkg/path.Symbol" strings or objects
	// {"package":"pkg/path","symbol":"Type.Method","role":"SINK"} — the
	// object form is needed for method subjects, where the string form
	// cannot split package path from symbol name.
	RootCauses   []RootCauseRef `json:"root_causes,omitempty"`
	ExploitModel string         `json:"exploit_model,omitempty"`
	// GoVersion requests the target toolchain ("1.21.13" or "go1.21.13") —
	// the version the release was built with. Resolved via SDK/GOTOOLCHAIN;
	// unavailability records a limitation, never a silent wrong-version run.
	GoVersion string `json:"go_version,omitempty"`
	// Expect lists acceptable verdicts; empty means informational only
	// (the case still counts toward distribution metrics).
	Expect []string `json:"expect,omitempty"`
	// Claims asserts per-condition claim results, e.g.
	// {"C-EXPOSED":"FALSE"}. A mismatch fails the case.
	Claims map[string]string `json:"expect_claims,omitempty"`
}

// Corpus is the case list plus an optional shared repository path.
type Corpus struct {
	Repo  string `json:"repo,omitempty"`
	Cases []Case `json:"cases"`
}

// RootCauseRef is a manual root-cause entry: "pkg/path.Symbol" sugar or the
// explicit domain.RootCause object form.
type RootCauseRef struct {
	domain.RootCause
}

// UnmarshalJSON accepts either a "pkg/path.Symbol" string (last dot splits
// package path from symbol) or a full RootCause object.
func (r *RootCauseRef) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		i := strings.LastIndex(s, ".")
		if i <= 0 {
			return fmt.Errorf("root_causes entry %q: want pkg/path.Symbol", s)
		}
		r.RootCause = domain.RootCause{
			Package:   s[:i],
			Symbol:    s[i+1:],
			Role:      domain.RootCauseSink,
			Mechanism: "provided manually via eval corpus",
		}
		return nil
	}
	return json.Unmarshal(b, &r.RootCause)
}

// Label returns the display name of a case.
func (c Case) Label() string {
	if c.ID != "" {
		return c.ID
	}
	return c.Vuln
}

// Result is the outcome of one corpus case.
type Result struct {
	Case    Case              `json:"case"`
	Verdict string            `json:"verdict,omitempty"`
	Reason  string            `json:"reason,omitempty"`
	Claims  map[string]string `json:"claims,omitempty"`
	Err     string            `json:"error,omitempty"`
	// ExpectOK is nil when the case carries no expectations.
	ExpectOK  *bool `json:"expect_ok,omitempty"`
	ClaimsOK  *bool `json:"claims_ok,omitempty"`
	FalseSafe bool  `json:"false_safe,omitempty"`
}

// Metrics is the aggregate evaluation report — the numbers the spec's
// stop criterion is expressed in.
type Metrics struct {
	Total      int            `json:"total"`
	Errors     int            `json:"errors"`
	ExpectPass int            `json:"expect_pass"`
	ExpectFail int            `json:"expect_fail"`
	NoExpect   int            `json:"informational"`
	Verdicts   map[string]int `json:"verdicts"`
	// FalseSafe — cases reported NOT_AFFECTED or NO_EXPLOIT_PATH_FOUND
	// while their expectation did not allow a safe verdict. The stop
	// criterion: this must stay zero.
	FalseSafe    int `json:"false_safe"`
	Inconclusive int `json:"inconclusive"`
	// ClaimsFail counts cases whose per-condition claim assertions did not
	// hold — a finer regression signal than verdicts alone.
	ClaimsFail int `json:"claims_fail"`
}

// Report pairs metrics with per-case results.
type Report struct {
	Metrics Metrics  `json:"metrics"`
	Results []Result `json:"results"`
}

var safeVerdicts = map[domain.Verdict]bool{
	domain.VerdictNotAffected:        true,
	domain.VerdictNoExploitPathFound: true,
}

// Record folds one finished case into the report.
func (r *Report) Record(c Case, verdict domain.Verdict, reason string, claims map[string]string, runErr error) {
	res := Result{Case: c, Claims: claims}
	if runErr != nil {
		res.Err = runErr.Error()
		r.Metrics.Errors++
	} else {
		res.Verdict = string(verdict)
		res.Reason = reason
		if r.Metrics.Verdicts == nil {
			r.Metrics.Verdicts = map[string]int{}
		}
		r.Metrics.Verdicts[res.Verdict]++
		if verdict == domain.VerdictInconclusive {
			r.Metrics.Inconclusive++
		}
	}
	if len(c.Expect) > 0 {
		ok := false
		for _, want := range c.Expect {
			if res.Verdict == want {
				ok = true
			}
		}
		res.ExpectOK = &ok
		if ok {
			r.Metrics.ExpectPass++
		} else {
			r.Metrics.ExpectFail++
			res.FalseSafe = safeVerdicts[verdict]
			if res.FalseSafe {
				r.Metrics.FalseSafe++
			}
		}
	} else {
		r.Metrics.NoExpect++
	}
	if len(c.Claims) > 0 {
		ok := true
		for id, want := range c.Claims {
			if res.Claims[id] != want {
				ok = false
			}
		}
		res.ClaimsOK = &ok
		if !ok {
			r.Metrics.ClaimsFail++
		}
	}
	r.Metrics.Total++
	r.Results = append(r.Results, res)
}

// Markdown renders the report as a reviewable table.
func (r Report) Markdown() string {
	var b strings.Builder
	b.WriteString("# Evaluation report\n\n")
	fmt.Fprintf(&b, "cases: %d | errors: %d | expect pass: %d | expect fail: %d | **false-safe: %d** | inconclusive: %d\n\n",
		r.Metrics.Total, r.Metrics.Errors, r.Metrics.ExpectPass, r.Metrics.ExpectFail,
		r.Metrics.FalseSafe, r.Metrics.Inconclusive)
	if r.Metrics.ClaimsFail > 0 {
		fmt.Fprintf(&b, "claim mismatches: %d\n\n", r.Metrics.ClaimsFail)
	}
	if len(r.Metrics.Verdicts) > 0 {
		var vs []string
		for v, n := range r.Metrics.Verdicts {
			vs = append(vs, fmt.Sprintf("%s=%d", v, n))
		}
		sort.Strings(vs)
		fmt.Fprintf(&b, "verdicts: %s\n\n", strings.Join(vs, " "))
	}
	b.WriteString("| case | verdict | expect | claims | note |\n|---|---|---|---|---|\n")
	for _, res := range r.Results {
		v := res.Verdict
		if res.Err != "" {
			v = "ERROR"
		}
		exp := "-"
		if res.ExpectOK != nil {
			if *res.ExpectOK {
				exp = "ok"
			} else {
				exp = "FAIL"
			}
		}
		cl := "-"
		if res.ClaimsOK != nil {
			if *res.ClaimsOK {
				cl = "ok"
			} else {
				cl = "FAIL"
			}
		}
		note := ""
		if res.FalseSafe {
			note = "**FALSE-SAFE**"
		} else if res.Err != "" {
			note = res.Err
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", res.Case.Label(), v, exp, cl, note)
	}
	return b.String()
}
