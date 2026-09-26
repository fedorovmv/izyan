package toolchain

import (
	"context"
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"go1.21.13": "1.21.13",
		"1.21.13":   "1.21.13",
		"go1.22":    "1.22",
		"":          "",
	} {
		if got := Normalize(in); got != want {
			t.Errorf("Normalize(%q)=%q want %q", in, got, want)
		}
	}
}

func TestResolveLocal(t *testing.T) {
	ctx := context.Background()
	cur, err := LocalVersion(ctx)
	if err != nil {
		t.Skipf("no go in PATH: %v", err)
	}
	tc, lims := Resolve(ctx, "")
	if tc.Mode != ModeLocal || tc.Version != cur {
		t.Fatalf("empty want: %+v", tc)
	}
	tc, lims = Resolve(ctx, "go"+cur)
	if tc.Mode != ModeLocal {
		t.Fatalf("matching want should stay local, got %s", tc.Mode)
	}
	if len(lims) != 0 {
		t.Fatalf("matching local should be silent, got %v", lims)
	}
}

func TestResolveUnavailable(t *testing.T) {
	ctx := context.Background()
	cur, err := LocalVersion(ctx)
	if err != nil {
		t.Skipf("no go in PATH: %v", err)
	}
	// A version that cannot exist locally or as an SDK.
	tc, lims := Resolve(ctx, "0.0.1")
	if !tc.Mismatch {
		t.Fatalf("want mismatch on impossible version, got %+v", tc)
	}
	if tc.Version != cur {
		t.Fatalf("fallback must keep local version, got %q", tc.Version)
	}
	if len(lims) == 0 || !strings.Contains(lims[len(lims)-1], "unavailable") {
		t.Fatalf("missing mismatch limitation: %v", lims)
	}
}

func TestResolveSDKLayout(t *testing.T) {
	// sdkToolchain must reject a missing SDK cleanly.
	if _, ok := sdkToolchain(context.Background(), "0.0.0-nonexistent"); ok {
		t.Fatal("phantom SDK accepted")
	}
}
