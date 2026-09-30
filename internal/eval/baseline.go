// Standalone govulncheck baseline: the differentiation evidence. Each
// real-dep case records what unmodified `govulncheck -mode source` says
// about the advisory on the generated product — reachable, package-level
// import only, silent despite knowing the advisory, not in its DB, or a
// tool error — so the report can compare it against the analyzer verdict.
package eval

import (
	"context"
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/goanalysis"
)

// Baseline outcome labels, recorded on Result.Baseline.
const (
	BaselineReachable    = "reachable"     // finding with a function-level trace
	BaselinePackageLevel = "package-level" // imported package, no symbol trace
	BaselineModuleLevel  = "module-level"
	BaselineSilent       = "silent"    // advisory in the DB, no finding emitted
	BaselineNotInDB      = "not-in-db" // advisory absent from the DB snapshot
	BaselineError        = "error"     // govulncheck did not run cleanly
)

// Baseline runs standalone govulncheck on dir and classifies what it
// reports about v. The runner must not be the corpus-wide caching one —
// generated products differ per case.
func Baseline(ctx context.Context, r goanalysis.Runner, dir string, v domain.Vulnerability, build domain.ProductSnapshot) string {
	raw, err := r.RunGovulncheck(ctx, dir, build)
	if err != nil {
		return fmt.Sprintf("%s: %v", BaselineError, err)
	}
	res, err := goanalysis.Parse(raw)
	if err != nil {
		return fmt.Sprintf("%s: %v", BaselineError, err)
	}
	fs := res.ForVulnerability(v)
	packageLevel := false
	for _, f := range fs {
		for _, fr := range f.Trace {
			if fr.Function != "" {
				return BaselineReachable
			}
			if fr.Package != "" {
				packageLevel = true
			}
		}
	}
	if packageLevel {
		return BaselinePackageLevel
	}
	if len(fs) > 0 {
		return BaselineModuleLevel
	}
	if res.Covers(v) {
		return BaselineSilent
	}
	return BaselineNotInDB
}
