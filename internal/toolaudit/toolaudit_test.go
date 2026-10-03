package toolaudit

import (
	"context"
	"os/exec"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func TestRunRecordsExecution(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	var got []domain.ToolExecution
	ctx := WithRecorder(context.Background(),
		&Recorder{Sink: func(tx domain.ToolExecution) { got = append(got, tx) }})
	stdout, _, err := Run(ctx, "go", "1.99.0", "", "go", nil, "version")
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(stdout) == 0 {
		t.Fatal("empty stdout")
	}
	if len(got) != 1 {
		t.Fatalf("records=%d want 1", len(got))
	}
	rec := got[0]
	if rec.Tool != "go" || rec.Version != "1.99.0" {
		t.Fatalf("tool/version: %+v", rec)
	}
	if rec.ExitCode != 0 || rec.StdoutSHA256 == "" {
		t.Fatalf("bad record: %+v", rec)
	}
	if len(rec.Args) != 1 || rec.Args[0] != "version" {
		t.Fatalf("args: %v", rec.Args)
	}
}

func TestRunRecordsFailure(t *testing.T) {
	ctx := WithRecorder(context.Background(),
		&Recorder{Sink: func(tx domain.ToolExecution) {
			if tx.ExitCode != -1 || tx.Error == "" {
				t.Fatalf("failed exec must record exit -1 and error, got %+v", tx)
			}
		}})
	_, _, err := Run(ctx, "nonexistent", "", "", "definitely-no-such-binary-xyz", nil)
	if err == nil {
		t.Fatal("expected exec error")
	}
}

func TestRunWithoutRecorder(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	// No recorder in ctx: must not panic, still returns output.
	stdout, _, err := Run(context.Background(), "go", "", "", "go", nil, "version")
	if err != nil || len(stdout) == 0 {
		t.Fatalf("run: %v out=%q", err, stdout)
	}
}
