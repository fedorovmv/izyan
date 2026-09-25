package affected

import (
	"strings"

	"golang.org/x/mod/semver"

	"example.com/vuln-analyzer/internal/domain"
)

// affectedByRanges reports whether version falls inside any of the ranges.
// Semantics follow the OSV spec: [introduced, fixed) or [introduced,
// last_affected]. An empty introduced matches all versions; an absent upper
// bound means affected without end.
func affectedByRanges(version string, ranges []domain.VersionRange) bool {
	v := normalizeVersion(version)
	if v == "" {
		return false
	}
	for _, r := range ranges {
		if inRange(v, r) {
			return true
		}
	}
	return false
}

func inRange(v string, r domain.VersionRange) bool {
	if r.Introduced != "" {
		lo := normalizeVersion(r.Introduced)
		if lo != "" && semver.Compare(v, lo) < 0 {
			return false
		}
	}
	if r.Fixed != "" {
		hi := normalizeVersion(r.Fixed)
		if hi == "" || semver.Compare(v, hi) >= 0 {
			return false
		}
		return true
	}
	if r.LastAffected != "" {
		hi := normalizeVersion(r.LastAffected)
		if hi == "" {
			return false
		}
		return semver.Compare(v, hi) <= 0
	}
	return true
}

// normalizeVersion maps OSV/Go version spellings onto canonical semver.
// "0" and "0.0.0" mark the beginning of history; "" is not a version.
// Returns "" when the input cannot be interpreted as semver.
func normalizeVersion(s string) string {
	s = strings.TrimSpace(s)
	switch s {
	case "", "0":
		return ""
	}
	if !strings.HasPrefix(s, "v") {
		s = "v" + s
	}
	if !semver.IsValid(s) {
		return ""
	}
	return semver.Canonical(s)
}
