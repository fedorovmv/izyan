package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

// Memory budget enforcement for the analysis process. Real products can
// pull arbitrarily large dependency graphs into the source index; without
// a ceiling the analyzer has eaten whole-machine memory on products like
// hashicorp/go-getter (aws-sdk-scale transitive trees).
//
// The mechanism is two-tier:
//
//   - debug.SetMemoryLimit(90% of budget) makes the runtime apply GC
//     pressure early — most runs stay under the budget cheaply.
//   - a watchdog samples real usage: crossing the budget cancels the
//     analysis context (subprocesses die, packages.Load aborts); if a
//     pure-Go loop keeps allocating past 150% anyway, the process exits —
//     a lost run is recoverable, a swapped-out host is not.
//
// A pure-Go loop does not notice ctx cancellation mid-scan; the hard exit
// is the honest guarantee for that case. Child processes (govulncheck,
// go) have separate heaps — cancellation kills them, but their own
// consumption is not bounded by this guard.
func applyMemoryLimit(ctx context.Context, budget int64) (context.Context, context.CancelFunc) {
	if budget <= 0 {
		return ctx, func() {}
	}
	debug.SetMemoryLimit(int64(float64(budget) * 0.9))
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(200 * time.Millisecond)
		defer t.Stop()
		overBudget := 0
		var lastFree time.Time
		for {
			select {
			case <-done:
				return
			case <-t.C:
				var m runtime.MemStats
				runtime.ReadMemStats(&m)
				// HeapSys+StackInuse is the memory the runtime actually
				// holds — the number that matters against machine RAM.
				used := int64(m.HeapSys) + int64(m.StackInuse)
				switch {
				case used > budget/2*3:
					// Past 150%: cancellation already went out; the
					// analysis may still not yield (pure-Go loop) — a
					// persistent hold means the host is at risk.
					overBudget++
					if overBudget >= 5 {
						fmt.Fprintf(os.Stderr,
							"analyzer: memory %.1fGiB held past 150%% of --mem-limit for over a second — aborting to protect the host\n",
							float64(used)/float64(int64(1)<<30))
						os.Exit(4)
					}
				case used > budget:
					overBudget = 0
					cancel()
					// HeapSys counts spans the runtime keeps mapped for
					// reuse — collectable garbage can look like retained
					// memory under this metric. Force a scavenge sweep so
					// the next sample reflects live heap; a truly live
					// hold does not shrink and still hits the 150% abort.
					if time.Since(lastFree) > time.Second {
						debug.FreeOSMemory()
						lastFree = time.Now()
					}
				default:
					overBudget = 0
				}
			}
		}
	}()
	return ctx, func() {
		close(done)
		cancel()
	}
}

// parseMemLimit parses a --mem-limit value: "4GiB", "512MiB", "2GB",
// "800MB", a bare byte count, or "0"/"off" to disable the guard.
func parseMemLimit(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" || strings.EqualFold(s, "off") {
		return 0, nil
	}
	type suffix struct {
		name string
		mult float64
	}
	// Longest suffixes first — "gib" must win over "b".
	for _, suf := range []suffix{
		{"gib", 1 << 30}, {"mib", 1 << 20}, {"kib", 1 << 10},
		{"gb", 1e9}, {"mb", 1e6}, {"kb", 1e3}, {"b", 1},
	} {
		if _, ok := strings.CutSuffix(strings.ToLower(s), suf.name); ok {
			n, err := strconv.ParseFloat(strings.TrimSpace(s[:len(s)-len(suf.name)]), 64)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("bad --mem-limit %q", s)
			}
			return int64(n * suf.mult), nil
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad --mem-limit %q (want e.g. 4GiB, 512MiB, 0)", s)
	}
	return n, nil
}
