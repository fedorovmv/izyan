package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
)

func TestPrintVersion(t *testing.T) {
	origVersion, origCommit, origDate := Version, Commit, Date
	defer func() {
		Version, Commit, Date = origVersion, origCommit, origDate
	}()

	captureOutput := func(fn func()) string {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatalf("os.Pipe failed: %v", err)
		}
		origStdout := os.Stdout
		os.Stdout = w
		defer func() {
			os.Stdout = origStdout
		}()

		outChan := make(chan string)
		go func() {
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			_ = r.Close()
			outChan <- buf.String()
		}()

		fn()
		_ = w.Close()
		return <-outChan
	}

	t.Run("default dev version", func(t *testing.T) {
		Version = "dev"
		Commit = "none"
		Date = "unknown"

		out := captureOutput(printVersion)
		if !strings.Contains(out, "izyan dev") {
			t.Errorf("expected 'izyan dev', got %q", out)
		}
	})

	t.Run("release version with commit and date", func(t *testing.T) {
		Version = "v1.0.0"
		Commit = "1234567"
		Date = "2026-10-03T12:00:00Z"

		out := captureOutput(printVersion)
		if !strings.Contains(out, "izyan v1.0.0 (commit 1234567, built 2026-10-03T12:00:00Z)") {
			t.Errorf("unexpected output: %q", out)
		}
	})
}
