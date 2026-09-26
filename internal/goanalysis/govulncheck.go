// Package goanalysis wraps Go-specific analysis tools. govulncheck is the
// primary reachability source per the governing spec; everything else is a
// targeted gap-filler.
package goanalysis

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/toolaudit"
)

// Runner executes govulncheck and returns the raw -json stream.
type Runner interface {
	RunGovulncheck(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error)
}

type ExecRunner struct {
	Bin string
	// Env carries the target toolchain (PATH/GOTOOLCHAIN) into the
	// govulncheck subprocess and, for source mode, the `go` it spawns.
	Env []string
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
	// r.Env carries the target toolchain (PATH/GOTOOLCHAIN): govulncheck
	// source mode loads stdlib through the `go` it finds in PATH.
	extraEnv := r.Env
	var args []string
	if build.BinaryPath != "" {
		// Binary mode reads the release artifact's embedded build info: the
		// real toolchain and module versions, not the source tree's claims.
		args = []string{"-json", "-mode", "binary", build.BinaryPath}
	} else {
		args = []string{"-json", "-mode", "source"}
		if len(build.BuildTags) > 0 {
			args = append(args, "-tags", strings.Join(build.BuildTags, ","))
		}
		args = append(args, "./...")
	}
	var env []string
	if build.GOOS != "" {
		env = append(env, "GOOS="+build.GOOS)
	}
	if build.GOARCH != "" {
		env = append(env, "GOARCH="+build.GOARCH)
	}
	env = append(env, fmt.Sprintf("CGO_ENABLED=%t", build.CGOEnabled))
	env = append(env, extraEnv...)
	stdout, stderr, err := toolaudit.Run(ctx, "govulncheck", "", dir, bin, env, args...)
	if err != nil {
		return stdout, fmt.Errorf("govulncheck: %w: %s", err, stderr)
	}
	return stdout, nil
}

// DBInformer is an optional Runner capability: it reports the local
// vulnerability database's identity/timestamp so a not-covered advisory can
// be explained ("DB snapshot older than the advisory").
type DBInformer interface {
	DBInfo(ctx context.Context) (string, error)
}

// DBInfo runs `govulncheck -version` and returns the vulndb lines.
func (r ExecRunner) DBInfo(ctx context.Context) (string, error) {
	bin := r.Bin
	if bin == "" {
		bin = "govulncheck"
	}
	out, _, err := toolaudit.Run(ctx, "govulncheck", "", "", bin, nil, "-version")
	if err != nil {
		return "", err
	}
	var db []string
	for _, ln := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(ln), "vulndb") || strings.Contains(strings.ToLower(ln), "updated") {
			db = append(db, strings.TrimSpace(ln))
		}
	}
	if len(db) == 0 {
		return strings.TrimSpace(string(out)), nil
	}
	return strings.Join(db, "; "), nil
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
	// KnownOSVs is the set of advisory ids (and aliases) present in the
	// vulnerability database govulncheck used. An advisory absent here was
	// never evaluated — silence is not evidence of no path.
	KnownOSVs map[string]bool
}

// Covers reports whether the vulnerability was in govulncheck's DB.
func (r Result) Covers(v domain.Vulnerability) bool {
	if r.KnownOSVs == nil {
		return false
	}
	if r.KnownOSVs[v.ID] {
		return true
	}
	for _, a := range v.Aliases {
		if r.KnownOSVs[a] {
			return true
		}
	}
	return false
}

// Parse decodes the govulncheck -json stream, keeping findings and the set
// of advisories the embedded database knows.
func Parse(raw []byte) (Result, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	res := Result{KnownOSVs: map[string]bool{}}
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
			res.KnownOSVs[finding.OSV] = true
			continue
		}
		if o, ok := msg["osv"]; ok {
			var doc struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
			}
			if err := json.Unmarshal(o, &doc); err == nil {
				res.KnownOSVs[doc.ID] = true
				for _, a := range doc.Aliases {
					res.KnownOSVs[a] = true
				}
			}
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
