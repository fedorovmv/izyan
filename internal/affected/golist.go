package affected

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/toolaudit"
)

// Module mirrors the `go list -m -json` output subset we rely on.
type Module struct {
	Path     string  `json:"Path"`
	Version  string  `json:"Version"`
	Main     bool    `json:"Main"`
	Indirect bool    `json:"Indirect"`
	Replace  *Module `json:"Replace"`
}

// EffectivePath/EffectiveVersion unwrap replace directives: the version that
// actually lands in the build is what matters for range matching.
func (m Module) EffectivePath() string {
	if m.Replace != nil && m.Replace.Path != "" {
		return m.Replace.Path
	}
	return m.Path
}

func (m Module) EffectiveVersion() string {
	if m.Replace != nil && m.Replace.Version != "" {
		return m.Replace.Version
	}
	return m.Version
}

// Package mirrors `go list -json` subset.
type Package struct {
	ImportPath string  `json:"ImportPath"`
	Standard   bool    `json:"Standard"`
	DepOnly    bool    `json:"DepOnly"`
	Module     *Module `json:"Module"`
}

// GoTool runs the go toolchain inside the analyzed repository. Implementations
// must return raw stdout; callers persist it as evidence. The string result
// names the actual evidence source (go list output vs vendor/modules.txt).
type GoTool interface {
	ListModules(ctx context.Context, dir string, build domain.ProductSnapshot) (raw []byte, source string, err error)
	ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error)
}

// ExecGoTool runs `go` subprocesses. Bin overrides the go binary and Env
// carries toolchain env (PATH/GOTOOLCHAIN) so checks execute under the
// target toolchain, not whatever happens to be in PATH. Version tags
// audit records with the resolved toolchain version.
type ExecGoTool struct {
	Bin     string
	Env     []string
	Version string
}

func (t ExecGoTool) bin() string {
	if t.Bin != "" {
		return t.Bin
	}
	return "go"
}

func (t ExecGoTool) ListModules(ctx context.Context, dir string, _ domain.ProductSnapshot) ([]byte, string, error) {
	const goList = "go list -m -json all"
	raw, err := runGo(ctx, t.bin(), t.Version, dir, t.Env, "list", "-m", "-json", "all")
	if err == nil {
		return raw, goList, nil
	}
	// Vendor mode: `go list -m all` refuses to run. modules.txt is the
	// authoritative record of what is actually vendored.
	mods, vErr := loadVendorModules(dir)
	if vErr != nil {
		return raw, goList, err
	}
	var buf bytes.Buffer
	for _, m := range mods {
		b, mErr := json.Marshal(m)
		if mErr != nil {
			return nil, goList, mErr
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return buf.Bytes(), "vendor/modules.txt", nil
}

func (t ExecGoTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	args := []string{"list", "-deps", "-test", "-json"}
	if len(build.BuildTags) > 0 {
		args = append(args, "-tags", strings.Join(build.BuildTags, ","))
	}
	args = append(args, "./...")
	return runGo(ctx, t.bin(), t.Version, dir, append(buildEnv(build), t.Env...), args...)
}

func buildEnv(build domain.ProductSnapshot) []string {
	var env []string
	if build.GOOS != "" {
		env = append(env, "GOOS="+build.GOOS)
	}
	if build.GOARCH != "" {
		env = append(env, "GOARCH="+build.GOARCH)
	}
	env = append(env, fmt.Sprintf("CGO_ENABLED=%t", build.CGOEnabled))
	return env
}

func runGo(ctx context.Context, bin, version, dir string, env []string, args ...string) ([]byte, error) {
	stdout, stderr, err := toolaudit.Run(ctx, "go", version, dir, bin, env, args...)
	if err != nil {
		return stdout, fmt.Errorf("go %v: %w: %s", args, err, stderr)
	}
	return stdout, nil
}

func decodeModules(b []byte) ([]Module, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var out []Module
	for dec.More() {
		var m Module
		if err := dec.Decode(&m); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func decodePackages(b []byte) ([]Package, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	var out []Package
	for dec.More() {
		var p Package
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// loadVendorModules parses vendor/modules.txt — the authoritative
// module list when the repository builds in vendor mode.
func loadVendorModules(dir string) ([]Module, error) {
	b, err := os.ReadFile(filepath.Join(dir, "vendor", "modules.txt"))
	if err != nil {
		return nil, err
	}
	return ParseVendorModules(b), nil
}

// ParseVendorModules extracts module entries from vendor/modules.txt.
// Header lines look like:
//
//	# example.com/mod v1.2.3
//	# old.com/mod v1.0.0 => fork.com/mod v1.5.0
//	# old.com/mod v1.0.0 => ./local/dir
func ParseVendorModules(b []byte) []Module {
	var mods []Module
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "# ") {
			continue // package line, meta line (##) or blank
		}
		fields := strings.Fields(strings.TrimPrefix(line, "# "))
		if len(fields) < 2 {
			continue
		}
		m := Module{Path: fields[0], Version: fields[1]}
		if len(fields) >= 4 && fields[2] == "=>" {
			m.Replace = &Module{Path: fields[3]}
			if len(fields) >= 5 {
				m.Replace.Version = fields[4]
			}
		}
		mods = append(mods, m)
	}
	return mods
}

// CachingTool memoizes GoTool results for one (repo, build) pair — in
// scan mode the same module/package listing serves every advisory.
func CachingTool(inner GoTool) GoTool { return &cachingTool{inner: inner} }

type cachingTool struct {
	inner GoTool
	mOnce sync.Once
	mRaw  []byte
	mSrc  string
	mErr  error
	pOnce sync.Once
	pRaw  []byte
	pErr  error
}

func (t *cachingTool) ListModules(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, string, error) {
	t.mOnce.Do(func() {
		t.mRaw, t.mSrc, t.mErr = t.inner.ListModules(ctx, dir, build)
	})
	return t.mRaw, t.mSrc, t.mErr
}

func (t *cachingTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	t.pOnce.Do(func() {
		t.pRaw, t.pErr = t.inner.ListPackages(ctx, dir, build)
	})
	return t.pRaw, t.pErr
}
