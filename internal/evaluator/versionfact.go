package evaluator

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/fedorovmv/izyan/internal/domain"
)

// VersionFact evaluates CONFIGURATION / BUILD_CONDITION conditions whose
// description asserts the required property reduces to a version fact:
//   - "in vulnerable versions the feature does not exist" — assertion about
//     the affected range; TRUE once version_affected is proven.
//   - "version must be prior to 1.83.1" / "at least 2.0" — explicit bound;
//     resolved module version is compared with semver.
//
// Only positive resolution is produced: when no pattern matches, the claim
// stays UNKNOWN for other evaluators/the fallback.
var (
	affectedRangeRe = regexp.MustCompile(`(?i)(vulnerable|affected|unpatched)\s+versions?`)
	absenceRe       = regexp.MustCompile(`(?i)(does not exist|not present|absent|no such|not implemented|disabled by default|not supported)`)
	lowerBoundRe    = regexp.MustCompile(`(?i)(prior to|before|older than|earlier than|below|less than|< ?|<= ?)\s*v?(\d+\.\d+(\.\d+)?)`)
	upperBoundRe    = regexp.MustCompile(`(?i)(at least|or later|or newer|>= ?|> ?|since|from)\s*v?(\d+\.\d+(\.\d+)?)`)
)

type VersionFact struct{}

func (VersionFact) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionConfiguration || cond.Kind == domain.ConditionBuild
}

func (VersionFact) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,

		Producer: "evaluator.VersionFact",
	}
	if c.Affected == nil || c.Affected.VersionAffected != domain.ClaimTrue {
		return claim
	}
	// VersionAffected/ResolvedVersion are attributed to SelectedModule —
	// a condition whose subjects live in another linked module (pending
	// or a different confirmed entry) cannot inherit the fact.
	if c.Affected.SelectedModule != "" {
		linked := linkedModules(c)
		subjects := condSubjects(cond)
		if len(subjects) == 0 && len(linked) > 1 {
			claim.Limitations = append(claim.Limitations,
				"version fact cannot be attributed to a module: condition has no subjects")
			return claim
		}
		for _, s := range subjects {
			m := domain.OwnerModule(s.Package, linked)
			if m == "" && !strings.Contains(strings.Split(s.Package, "/")[0], ".") {
				for _, candidate := range linked {
					if candidate == "std" || candidate == "stdlib" {
						if m != "" {
							m = ""
							break
						}
						m = candidate
					}
				}
			}
			if m != c.Affected.SelectedModule {
				if m == "" {
					claim.Limitations = append(claim.Limitations, fmt.Sprintf(
						"version fact is attributed to module %s; subject %s has no known module owner",
						c.Affected.SelectedModule, s.Package+"."+s.Symbol))
					return claim
				}
				claim.Limitations = append(claim.Limitations, fmt.Sprintf(
					"version fact is attributed to module %s; subject %s belongs to module %s",
					c.Affected.SelectedModule, s.Package+"."+s.Symbol, m))
				return claim
			}
		}
	}
	desc := cond.Description
	resolved := "v" + strings.TrimPrefix(c.Affected.ResolvedVersion, "v")

	// Explicit bound: "must be prior to 1.83.1" -> resolved < bound.
	if m := lowerBoundRe.FindStringSubmatch(desc); m != nil {
		bound := "v" + m[2]
		if semver.IsValid(resolved) && semver.IsValid(bound) && semver.Compare(resolved, bound) < 0 {
			claim.Result = domain.ClaimTrue
			claim.Explanation = fmt.Sprintf("resolved version %s satisfies %q", resolved, m[0])
		}
	} else if m := upperBoundRe.FindStringSubmatch(desc); m != nil {
		bound := "v" + m[2]
		if semver.IsValid(resolved) && semver.IsValid(bound) && semver.Compare(resolved, bound) >= 0 {
			claim.Result = domain.ClaimTrue
			claim.Explanation = fmt.Sprintf("resolved version %s satisfies %q", resolved, m[0])
		}
	} else if affectedRangeRe.MatchString(desc) && absenceRe.MatchString(desc) {
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf(
			"advisory asserts the property holds in the vulnerable range; resolved version %s is confirmed affected",
			c.Affected.ResolvedVersion)
	}
	if claim.Result != domain.ClaimTrue {
		return claim
	}
	claim.Limitations = append(claim.Limitations,
		"derived from advisory/model text, not re-verified in dependency source — assertion: "+
			truncate(desc, 200))
	for _, id := range c.Affected.EvidenceIDs {
		claim.EvidenceIDs = appendUniqueID(claim.EvidenceIDs, id)
	}
	return claim
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
