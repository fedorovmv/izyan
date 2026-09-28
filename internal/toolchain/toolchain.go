// Package toolchain resolves the Go toolchain the analysis must run
// against. Release binaries are built with a toolchain that may differ
// from the developer's local `go`, and stdlib/runtime advisories are
// meaningless when source analysis reads the wrong GOROOT.
//
// Resolution order (CI may be offline):
//  1. local `go` when it already matches the target;
//  2. an installed golang.org/dl SDK at ~/sdk/go<version>;
//  3. GOTOOLCHAIN=go<version> — Go ≥1.21 downloads it on demand into the
//     module cache (needs network once);
//
// otherwise the local toolchain is kept and a limitation records the
// mismatch — analyzing under the wrong GOROOT silently is not allowed.
//
// Docker is a run mode, not a toolchain: a golang:<target> image bundles
// the analyzer binary and the target `go`; inside it resolution is just
// "local". See docs/dev/plans/toolchain-plan.md.
package toolchain

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"example.com/vuln-analyzer/internal/toolaudit"
)

// Mode names how the target toolchain is provided.
type Mode string

const (
	ModeLocal       Mode = "local"       // target == local, or no target requested
	ModeSDK         Mode = "sdk"         // ~/sdk/go<ver> (golang.org/dl), offline-capable
	ModeGoToolchain Mode = "gotoolchain" // GOTOOLCHAIN env, Go downloads on demand
)

// Toolchain carries everything subprocesses and the source index need to
// work under a specific Go version.
type Toolchain struct {
	Version string   // resolved version without "go" prefix ("1.21.13"); "" = whatever local runs
	Mode    Mode     // provisioning strategy actually used
	GoBin   string   // go binary path; "go" = PATH lookup
	Env     []string // env additions for subprocesses (PATH / GOTOOLCHAIN)
	GOROOT  string   // host path of the toolchain's GOROOT (source truth)
	// Mismatch is true when the caller asked for a version we could not
	// provide — the toolchain fields then describe the local fallback.
	Mismatch bool
}

// EnvFor appends the toolchain environment to a base env list.
func (t Toolchain) EnvFor(base []string) []string {
	if len(t.Env) == 0 {
		return base
	}
	return append(base, t.Env...)
}

var sdkVersionRE = regexp.MustCompile(`^go?(\d+\.\d+(?:\.\d+)?(?:rc\d+|beta\d+)?)$`)

// Normalize accepts "go1.21.13" or "1.21.13" and returns the bare version.
func Normalize(v string) string {
	v = strings.TrimSpace(v)
	if m := sdkVersionRE.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return strings.TrimPrefix(v, "go")
}

// LocalVersion reports the version of `go` in PATH.
func LocalVersion(ctx context.Context) (string, error) {
	return goVersion(ctx, "go", nil)
}

// Resolve picks the toolchain for target version `want` ("" or matching
// local → ModeLocal). It returns the toolchain plus human-readable
// limitation notes for the case record.
func Resolve(ctx context.Context, want string) (Toolchain, []string) {
	want = Normalize(want)
	cur, err := LocalVersion(ctx)
	if err != nil {
		return Toolchain{Mode: ModeLocal, GoBin: "go"},
			[]string{fmt.Sprintf("cannot determine local go version: %v", err)}
	}
	local := Toolchain{
		Version: cur, Mode: ModeLocal, GoBin: "go",
		GOROOT: goEnv(ctx, "go", nil, "GOROOT"),
	}
	if want == "" || want == cur {
		return local, nil
	}

	// Strategy 1: pre-installed golang.org/dl SDK — works offline.
	if tc, ok := sdkToolchain(ctx, want); ok {
		return tc, []string{fmt.Sprintf(
			"target toolchain go%s provided by installed SDK %s", want, tc.GOROOT)}
	}

	// Strategy 2: GOTOOLCHAIN auto-download (Go ≥1.21, needs network once).
	env := []string{"GOTOOLCHAIN=go" + want}
	if v, err := goVersion(ctx, "go", env); err == nil && v == want {
		return Toolchain{
				Version: want, Mode: ModeGoToolchain, GoBin: "go",
				Env:    env,
				GOROOT: goEnv(ctx, "go", env, "GOROOT"),
			}, []string{fmt.Sprintf(
				"target toolchain go%s provided via GOTOOLCHAIN auto-download", want)}
	}

	local.Mismatch = true
	return local, []string{fmt.Sprintf(
		"target toolchain go%s unavailable (no ~/sdk/go%s, GOTOOLCHAIN download failed); analysis ran on local go%s — stdlib source results may reflect the wrong version",
		want, want, cur)}
}

// sdkToolchain resolves ~/sdk/go<ver> installed via
// `go install golang.org/dl/go<ver>@latest && go<ver> download`.
func sdkToolchain(ctx context.Context, want string) (Toolchain, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Toolchain{}, false
	}
	root := filepath.Join(home, "sdk", "go"+want)
	bin := filepath.Join(root, "bin", "go")
	if st, err := os.Stat(bin); err != nil || st.IsDir() {
		return Toolchain{}, false
	}
	// Verify the SDK is fully downloaded (`go<ver> download` was run).
	if v, err := goVersion(ctx, bin, nil); err != nil || v != want {
		return Toolchain{}, false
	}
	return Toolchain{
		Version: want, Mode: ModeSDK, GoBin: bin,
		Env:    []string{"PATH=" + filepath.Dir(bin) + string(os.PathListSeparator) + os.Getenv("PATH")},
		GOROOT: root,
	}, true
}

// goVersion runs `<bin> version` and extracts "1.21.13" from
// "go version go1.21.13 darwin/arm64".
func goVersion(ctx context.Context, bin string, env []string) (string, error) {
	out, err := run(ctx, bin, env, "version")
	if err != nil {
		return "", err
	}
	// "go version go1.21.13 darwin/arm64" — the token after "version".
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "version" && i+1 < len(fields) {
			return Normalize(fields[i+1]), nil
		}
	}
	return "", fmt.Errorf("unparseable go version output: %q", out)
}

// goEnv reads a `go env` value under the given env (module-cache GOROOTs
// are host-readable, so source analysis can read them directly).
func goEnv(ctx context.Context, bin string, env []string, key string) string {
	out, err := run(ctx, bin, env, "env", key)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func run(ctx context.Context, bin string, env []string, args ...string) (string, error) {
	out, _, err := toolaudit.Run(ctx, filepath.Base(bin), "", "", bin, env, args...)
	if err != nil {
		return "", fmt.Errorf("%s %v: %w", bin, args, err)
	}
	return string(out), nil
}
