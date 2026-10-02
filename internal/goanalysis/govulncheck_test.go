package goanalysis

import (
	"testing"
)

func TestFindingHasCallPath(t *testing.T) {
	// Finding with function-level call path
	fWithFunc := Finding{
		OSV: "GO-2026-1234",
		Trace: []TraceFrame{
			{Package: "example.com/lib", Function: "VulnFunc"},
			{Package: "example.com/app", Function: "main"},
		},
	}
	if !fWithFunc.HasCallPath() {
		t.Fatalf("expected HasCallPath to be true for finding with functions")
	}
	cp := fWithFunc.CallPath()
	if len(cp.Frames) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(cp.Frames))
	}

	// Finding with only package/module level trace (no function)
	fWithoutFunc := Finding{
		OSV: "GO-2026-1234",
		Trace: []TraceFrame{
			{Package: "example.com/lib", Function: ""},
			{Module: "example.com/lib", Function: ""},
		},
	}
	if fWithoutFunc.HasCallPath() {
		t.Fatalf("expected HasCallPath to be false for package/module-only finding")
	}
	cpEmpty := fWithoutFunc.CallPath()
	if len(cpEmpty.Frames) != 0 {
		t.Fatalf("expected 0 frames for package/module-only finding, got %d", len(cpEmpty.Frames))
	}
}
