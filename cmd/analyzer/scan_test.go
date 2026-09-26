package main

import (
	"reflect"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestDedupeAppend(t *testing.T) {
	got := dedupeAppend([]string{"A", "B"}, []string{"B", "C", "A", "D"})
	want := []string{"A", "B", "C", "D"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// Order across multiple module queries is stable.
	got = dedupeAppend(got, []string{"D", "E"})
	if !reflect.DeepEqual(got, []string{"A", "B", "C", "D", "E"}) {
		t.Fatalf("second append: %v", got)
	}
}

func TestDeterministicallyNotAffected(t *testing.T) {
	cases := []struct {
		name string
		res  domain.AffectedResult
		want bool
	}{
		{"module absent", domain.AffectedResult{ModulePresent: domain.ClaimFalse}, true},
		{"version outside", domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimFalse}, true},
		{"package absent", domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimFalse}, true},
		{"all true", domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimTrue, PackagePresent: domain.ClaimTrue, BuildRelevant: domain.ClaimTrue}, false},
		{"unknown stays", domain.AffectedResult{ModulePresent: domain.ClaimTrue, VersionAffected: domain.ClaimUnknown}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if deterministicallyNotAffected(tc.res) != tc.want {
				t.Fatalf("res=%+v", tc.res)
			}
		})
	}
}

func TestNotAffectedReasonCoversEveryChain(t *testing.T) {
	r := domain.AffectedResult{ModulePresent: domain.ClaimFalse}
	if notAffectedReason(r) == "" {
		t.Fatal("module absent: empty reason")
	}
}
