// Package goanalysis wraps Go-specific analysis tools. govulncheck is the
// primary reachability source per the governing spec; everything else is a
// targeted gap-filler.
package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"example.com/vuln-analyzer/internal/domain"
)

// Runner executes govulncheck and returns the raw -json stream.
type Runner interface {
	RunGovulncheck(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error)
}

type ExecRunner struct {
	Bin string
}

// CachingRunner runs govulncheck once per (repo, build) — its output
// covers the whole vulnerability database, so a single run serves every
// advisory in a batch scan.
func CachingRunner(inner Runner) Runner { return &cachingRunner{inner: inner} }

type cachingRunner struct {
	inner Runner
	once  sync.Once
	out   []byte
	err   error
}

func (r *cachingRunner) RunGovulncheck(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	r.once.Do(func() {
		r.out, r.err = r.inner.RunGovulncheck(ctx, dir, build)
	})
	return r.out, r.err
}

func (r ExecRunner) RunGovulncheck(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	bin := r.Bin
	if bin == "" {
		bin = "govulncheck"
	}
	args := []string{"-json", "-mode", "source"}
	if len(build.BuildTags) > 0 {
		args = append(args, "-tags", strings.Join(build.BuildTags, ","))
	}
	args = append(args, "./...")
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	var env []string
	if build.GOOS != "" {
		env = append(env, "GOOS="+build.GOOS)
	}
	if build.GOARCH != "" {
		env = append(env, "GOARCH="+build.GOARCH)
	}
	env = append(env, fmt.Sprintf("CGO_ENABLED=%t", build.CGOEnabled))
	cmd.Env = append(cmd.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("govulncheck: %w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}

// Finding is the subset of the govulncheck -json finding message we use.
type Finding struct {
	OSV          string       `json:"osv"`
	FixedVersion string       `json:"fixed_version"`
	Trace        []TraceFrame `json:"trace"`
}

type TraceFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	} `json:"position"`
}

type Result struct {
	Findings []Finding
}

// Parse decodes the govulncheck -json stream, keeping only findings.
func Parse(raw []byte) (Result, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var res Result
	for dec.More() {
		var msg map[string]json.RawMessage
		if err := dec.Decode(&msg); err != nil {
			return res, fmt.Errorf("decode govulncheck stream: %w", err)
		}
		if f, ok := msg["finding"]; ok {
			var finding Finding
			if err := json.Unmarshal(f, &finding); err != nil {
				return res, fmt.Errorf("decode finding: %w", err)
			}
			res.Findings = append(res.Findings, finding)
		}
	}
	return res, nil
}

// ForVulnerability returns findings whose OSV id matches the vulnerability or
// one of its aliases.
func (r Result) ForVulnerability(v domain.Vulnerability) []Finding {
	var out []Finding
	for _, f := range r.Findings {
		if f.OSV == v.ID || hasString(v.Aliases, f.OSV) {
			out = append(out, f)
		}
	}
	return out
}

// TraceReaches reports whether any trace frame invokes the symbol. Function
// names may carry a receiver ("(*T).M"); the receiver is stripped before
// comparison.
func (f Finding) TraceReaches(sym domain.SymbolRef) bool {
	for _, fr := range f.Trace {
		if frameIsSymbol(fr, sym) {
			return true
		}
	}
	return false
}

func frameIsSymbol(fr TraceFrame, sym domain.SymbolRef) bool {
	if fr.Package != sym.Package {
		return false
	}
	fn := fr.Function
	if strings.HasPrefix(fn, "(") {
		if i := strings.Index(fn, ")."); i >= 0 {
			fn = fn[i+2:]
		}
	}
	fn = strings.TrimPrefix(fn, "*")
	// Receiver-qualified symbols ("Type.Method") must also match the frame's
	// receiver; bare symbols match on the function name alone.
	if i := strings.LastIndexByte(sym.Symbol, '.'); i >= 0 {
		recv := strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(fr.Receiver, "("), ")"), "*")
		return fn == sym.Symbol[i+1:] && recv == sym.Symbol[:i]
	}
	return fn == sym.Symbol
}

func hasString(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// CallPath converts a finding trace into the graph's normalized form.
func (f Finding) CallPath() domain.CallPath {
	cp := domain.CallPath{Frames: make([]domain.CallSite, 0, len(f.Trace))}
	for _, fr := range f.Trace {
		cs := domain.CallSite{Package: fr.Package, Function: fr.Function, Receiver: fr.Receiver}
		if fr.Position != nil {
			cs.File = fr.Position.Filename
			cs.Line = fr.Position.Line
		}
		cp.Frames = append(cp.Frames, cs)
	}
	return cp
}
