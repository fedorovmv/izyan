package main

import (
	"context"
	"runtime"
	"testing"
	"time"
)

func TestParseMemLimit(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"4GiB", 4 << 30},
		{"512MiB", 512 << 20},
		{"2GB", 2_000_000_000},
		{"800MB", 800_000_000},
		{"1KiB", 1 << 10},
		{"4096", 4096},
		{"0", 0},
		{"off", 0},
		{"", 0},
		{"1.5GiB", int64(1.5 * float64(int64(1)<<30))},
	}
	for _, c := range cases {
		got, err := parseMemLimit(c.in)
		if err != nil {
			t.Fatalf("parseMemLimit(%q): %v", c.in, err)
		}
		if got != c.want {
			t.Errorf("parseMemLimit(%q) = %d, want %d", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"bogus", "-1GiB", "GiB", "1e9x"} {
		if _, err := parseMemLimit(bad); err == nil {
			t.Errorf("parseMemLimit(%q): expected error", bad)
		}
	}
}

// A zero budget leaves the context untouched — the guard is opt-out.
func TestApplyMemoryLimitDisabled(t *testing.T) {
	ctx, stop := applyMemoryLimit(context.Background(), 0)
	defer stop()
	select {
	case <-ctx.Done():
		t.Fatal("disabled guard cancelled the context")
	default:
	}
}

// With the budget set between current usage and 150% of it, the watchdog
// cancels promptly without entering the hard-exit band.
func TestApplyMemoryLimitCancelsOverBudget(t *testing.T) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	used := int64(m.HeapSys) + int64(m.StackInuse)
	ctx, stop := applyMemoryLimit(context.Background(), int64(float64(used)*0.8))
	defer stop()
	select {
	case <-ctx.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("watchdog did not cancel the over-budget context")
	}
}
