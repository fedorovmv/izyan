package goanalysis

import (
	"context"
	"testing"
)

func TestInboundAuthFacts(t *testing.T) {
	ix := &Index{Dir: "../../testdata/authwire"}
	facts, err := ix.InboundAuthFacts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range facts {
		if f.Kind != "auth-middleware" || f.Direction != "inbound" {
			t.Fatalf("bad fact: %+v", f)
		}
		names = append(names, f.Target)
	}
	t.Logf("facts: %v", names)
	want := map[string]bool{"Use:authMw": true, "With:sessionCheck": true,
		"handler-wrap:authMw": true}
	for _, w := range []string{"Use:authMw", "With:sessionCheck"} {
		if !want[w] {
			t.Fatal("unreachable")
		}
	}
	got := map[string]bool{}
	for _, n := range names {
		got[n] = true
	}
	for w := range want {
		if !got[w] {
			t.Fatalf("missing %q in %v", w, names)
		}
	}
	if got["Use:plain"] {
		t.Fatal("non-auth wrapper reported as auth middleware")
	}
}
