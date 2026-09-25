package affected

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
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
// must return raw stdout; callers persist it as evidence.
type GoTool interface {
	ListModules(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error)
	ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error)
}

type ExecGoTool struct{}

func (ExecGoTool) ListModules(ctx context.Context, dir string, _ domain.ProductSnapshot) ([]byte, error) {
	return runGo(ctx, dir, nil, "list", "-m", "-json", "all")
}

func (ExecGoTool) ListPackages(ctx context.Context, dir string, build domain.ProductSnapshot) ([]byte, error) {
	args := []string{"list", "-deps", "-test", "-json"}
	if len(build.BuildTags) > 0 {
		args = append(args, "-tags", strings.Join(build.BuildTags, ","))
	}
	args = append(args, "./...")
	return runGo(ctx, dir, buildEnv(build), args...)
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

func runGo(ctx context.Context, dir string, env []string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(cmd.Environ(), env...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), fmt.Errorf("go %v: %w: %s", args, err, stderr.String())
	}
	return stdout.Bytes(), nil
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
