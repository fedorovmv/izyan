package affected

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestAffectedByRanges(t *testing.T) {
	ranges := []domain.VersionRange{
		{Introduced: "0", Fixed: "0.23.0"},
	}
	cases := []struct {
		version string
		want    bool
	}{
		{"v0.22.0", true},
		{"v0.3.7", true},
		{"v0.23.0", false},
		{"v1.0.0", false},
		{"v0.0.0-20230101000000-abcdef123456", true},
		{"", false},
		{"(devel)", false},
	}
	for _, tc := range cases {
		if got := affectedByRanges(tc.version, ranges); got != tc.want {
			t.Errorf("affectedByRanges(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestAffectedByRangesLastAffected(t *testing.T) {
	ranges := []domain.VersionRange{
		{Introduced: "1.2.0", LastAffected: "1.4.0"},
	}
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"v1.1.9", false},
		{"v1.2.0", true},
		{"v1.4.0", true},
		{"v1.4.1", false},
	} {
		if got := affectedByRanges(tc.version, ranges); got != tc.want {
			t.Errorf("affectedByRanges(%q) = %v, want %v", tc.version, got, tc.want)
		}
	}
}

func TestAffectedByRangesOpenEnded(t *testing.T) {
	ranges := []domain.VersionRange{{Introduced: "2.0.0"}}
	if !affectedByRanges("v9.9.9", ranges) {
		t.Error("open-ended introduced range should match any later version")
	}
	if affectedByRanges("v1.0.0", ranges) {
		t.Error("version below introduced should not match")
	}
}
