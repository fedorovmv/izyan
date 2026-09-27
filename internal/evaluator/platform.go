package evaluator

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"

	"example.com/vuln-analyzer/internal/domain"
)

// Platform evaluates PLATFORM_CONDITION and RUNTIME_CONDITION claims whose
// params declare snapshot facts — goos, goarch, go_version bounds — instead
// of code properties. Facts come from the product snapshot (and the binary
// build info when --binary was supplied), never inferred: a mismatch is a
// factual FALSE, a missing snapshot fact stays UNKNOWN.
type Platform struct{}

func (Platform) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionPlatform || cond.Kind == domain.ConditionRuntime
}

var goVersionBound = regexp.MustCompile(`^(<=|>=|<|>|=|==)?\s*v?(\d+\.\d+(?:\.\d+)?)$`)
var goVersionFrom = regexp.MustCompile(`go(\d+\.\d+(?:\.\d+)?)`)

// productGoVersion extracts the toolchain that built the product:
// ReleaseGoVersion (--binary metadata) wins over the local `go version`
// snapshot string.
func productGoVersion(p domain.ProductSnapshot) string {
	v := p.ReleaseGoVersion
	if v == "" {
		v = p.GoVersion
	}
	if m := goVersionFrom.FindStringSubmatch(v); m != nil {
		return "v" + m[1]
	}
	return ""
}

func (Platform) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.Platform",
	}
	type check struct {
		name  string
		want  string
		got   string
		ok    bool // the snapshot actually supplies this fact
		holds bool
	}
	var checks []check
	for _, name := range []string{"goos", "goarch"} {
		want := cond.Params[name]
		if want == "" {
			continue
		}
		got := c.Product.GOOS
		if name == "goarch" {
			got = c.Product.GOARCH
		}
		checks = append(checks, check{
			name: name, want: want, got: got,
			ok:    got != "",
			holds: strings.EqualFold(got, want),
		})
	}
	if bound := cond.Params["go_version"]; bound != "" {
		if m := goVersionBound.FindStringSubmatch(strings.TrimSpace(bound)); m != nil {
			got := productGoVersion(c.Product)
			h := false
			if got != "" {
				op := m[1]
				cmp := semver.Compare(got, "v"+m[2])
				switch op {
				case "<":
					h = cmp < 0
				case "<=":
					h = cmp <= 0
				case ">":
					h = cmp > 0
				case ">=":
					h = cmp >= 0
				default: // =, ==
					h = cmp == 0
				}
			}
			checks = append(checks, check{
				name: "go_version", want: bound, got: got,
				ok: got != "", holds: h,
			})
		} else {
			claim.Limitations = append(claim.Limitations,
				"unparseable go_version bound: "+bound)
		}
	}
	if len(checks) == 0 {
		claim.Limitations = append(claim.Limitations,
			"condition declares no evaluable platform params (goos/goarch/go_version)")
		return claim
	}
	var missing, violated []string
	for _, ch := range checks {
		if !ch.ok {
			missing = append(missing, ch.name)
			continue
		}
		if !ch.holds {
			violated = append(violated, fmt.Sprintf("%s: want %s, product is %s", ch.name, ch.want, ch.got))
		}
	}
	switch {
	case len(violated) > 0:
		claim.Result = domain.ClaimFalse
		claim.Explanation = "snapshot fact mismatch: " + strings.Join(violated, "; ")
		claim.Limitations = append(claim.Limitations,
			"FALSE is a snapshot fact verdict, not a code-scope claim")
	case len(missing) > 0:
		claim.Limitations = append(claim.Limitations,
			"snapshot does not record: "+strings.Join(missing, ", "))
	default:
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf("%d platform fact(s) satisfied", len(checks))
	}
	return claim
}
