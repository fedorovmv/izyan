// Package toolaudit records external tool executions into the case's
// audit trail (spec §22 tool_executions: which tool ran, with what
// arguments, exit code, duration and output hashes).
//
// The recorder rides in context: shared tool wrappers (the cached
// govulncheck runner and go tool in scan mode) are built before a case
// exists, so executions are attributed through the context of whichever
// case currently runs them.
package toolaudit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os/exec"
	"time"

	"example.com/vuln-analyzer/internal/domain"
)

type ctxKey struct{}

// Recorder persists audit records. Sink is nil-safe — executions without
// a sink are simply not recorded (unit tests, ad-hoc tool use).
type Recorder struct {
	Sink func(domain.ToolExecution)
}

func (r *Recorder) Record(t domain.ToolExecution) {
	if r == nil || r.Sink == nil {
		return
	}
	r.Sink(t)
}

// WithRecorder attaches a recorder to ctx; every Run under this context
// is recorded.
func WithRecorder(ctx context.Context, r *Recorder) context.Context {
	return context.WithValue(ctx, ctxKey{}, r)
}

// RecorderFrom returns the recorder attached to ctx, or nil.
func RecorderFrom(ctx context.Context) *Recorder {
	r, _ := ctx.Value(ctxKey{}).(*Recorder)
	return r
}

// Run executes name args in dir with env appended to the ambient
// environment, records the execution through the context's recorder,
// and returns the raw stdout/stderr so callers keep their own error
// handling. version tags the record when the caller knows the tool's
// version (e.g. the resolved toolchain); pass "" otherwise.
func Run(ctx context.Context, tool, version, dir, name string, env []string, args ...string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}
	var so, se bytes.Buffer
	cmd.Stdout, cmd.Stderr = &so, &se
	start := time.Now()
	err = cmd.Run()
	rec := domain.ToolExecution{
		Tool:         tool,
		Version:      version,
		Dir:          dir,
		Args:         args,
		DurationMs:   time.Since(start).Milliseconds(),
		StdoutSHA256: hashOf(so.Bytes()),
		StderrSHA256: hashOf(se.Bytes()),
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			rec.ExitCode = ee.ExitCode()
		} else {
			rec.ExitCode = -1 // never started / killed by ctx cancel
		}
		rec.Error = err.Error()
	}
	if r := RecorderFrom(ctx); r != nil {
		r.Record(rec)
	}
	return so.Bytes(), se.Bytes(), err
}

func hashOf(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
