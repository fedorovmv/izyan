// Product materialization: corpus cases may name a directory of committed
// product sources plus a dep-version pin set instead of a repository. The
// harness assembles a buildable module under <corpus>/.gen/<case-id> —
// go.mod and go.sum are generated there, so no vulnerable manifest ever
// lives in the tree (scanners that read manifests see no vulnerable
// requires).
package eval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"example.com/vuln-analyzer/internal/toolaudit"
)

// Gen materializes generated-manifest products. GoBin runs `go mod tidy`
// (default "go"); Env carries the resolved toolchain environment into the
// subprocess.
type Gen struct {
	GoBin string
	Env   []string
	Force bool
}

// Materialize builds the runnable module for a product case into
// genRoot/<sanitized-id> and returns its path. The product directory is
// copied verbatim except that committed go.mod/go.sum are rejected —
// manifests are generated, not shipped.
func (g Gen) Materialize(ctx context.Context, c Case, corpusDir, genRoot string) (string, error) {
	if c.Product == "" {
		return "", fmt.Errorf("case %s: no product", c.Label())
	}
	if c.Module == "" {
		return "", fmt.Errorf("case %s: product requires module", c.Label())
	}
	src := c.Product
	if !filepath.IsAbs(src) {
		src = filepath.Join(corpusDir, src)
	}
	name := sanitizeFileName(c.Label())
	dst := filepath.Join(genRoot, name)
	// The label reaches the filesystem: a dot-only name resolves outside
	// genRoot (".." -> its parent) and copyProduct would remove that
	// directory. Reject before any filesystem operation.
	if name == "" || name == "." || name == ".." ||
		filepath.Dir(dst) != filepath.Clean(genRoot) {
		return "", fmt.Errorf("case %s: unsafe generated dir name %q", c.Label(), name)
	}

	sig, sigErr := computeGenSig(src, c)
	if sigErr == nil && !g.Force {
		sigPath := filepath.Join(dst, ".gen-sig")
		if oldSig, err := os.ReadFile(sigPath); err == nil && string(oldSig) == sig {
			if _, err := os.Stat(filepath.Join(dst, "go.mod")); err == nil {
				return dst, nil
			}
		}
	}

	if err := copyProduct(src, dst); err != nil {
		return "", fmt.Errorf("case %s: %w", c.Label(), err)
	}
	if err := writeGoMod(dst, c); err != nil {
		return "", err
	}
	gobin := g.GoBin
	if gobin == "" {
		gobin = "go"
	}
	_, stderr, err := toolaudit.Run(ctx, "go", "", dst, gobin, g.Env, "mod", "tidy")
	if err != nil {
		return "", fmt.Errorf("case %s: go mod tidy: %w: %s", c.Label(), err, strings.TrimSpace(string(stderr)))
	}
	if sig != "" {
		_ = os.WriteFile(filepath.Join(dst, ".gen-sig"), []byte(sig), 0o644)
	}
	return dst, nil
}

func computeGenSig(src string, c Case) (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "mod:%s;go:%s\n", c.Module, c.GoVersion)
	keys := make([]string, 0, len(c.Deps))
	for k := range c.Deps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(h, "dep:%s=%s\n", k, c.Deps[k])
	}
	err := filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		fmt.Fprintf(h, "f:%s;sz:%d;mtime:%d\n", rel, info.Size(), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// copyProduct clones the product source tree into dst, refusing any
// committed manifest — go.mod/go.sum in a product dir would shadow the
// generated pins.
func copyProduct(src, dst string) error {
	// dst is wiped below: refuse to run when it would touch the source
	// tree itself or anything outside an independent directory.
	srcAbs, err1 := filepath.Abs(src)
	dstAbs, err2 := filepath.Abs(dst)
	if err1 != nil || err2 != nil || srcAbs == dstAbs ||
		strings.HasPrefix(dstAbs, srcAbs+string(os.PathSeparator)) ||
		strings.HasPrefix(srcAbs, dstAbs+string(os.PathSeparator)) {
		return fmt.Errorf("refusing to copy %q into %q", src, dst)
	}
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		if base := d.Name(); base == "go.mod" || base == "go.sum" {
			return fmt.Errorf("product source contains %s — manifests are generated, not committed", rel)
		}
		return copyFile(p, filepath.Join(dst, rel))
	})
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

// writeGoMod renders the generated manifest: the case's module name plus
// its dep pins, sorted for a stable diff.
func writeGoMod(dir string, c Case) error {
	var b strings.Builder
	fmt.Fprintf(&b, "module %s\n\ngo 1.23\n", c.Module)
	if len(c.Deps) > 0 {
		var names []string
		for m := range c.Deps {
			names = append(names, m)
		}
		sort.Strings(names)
		b.WriteString("\nrequire (\n")
		for _, m := range names {
			fmt.Fprintf(&b, "\t%s %s\n", m, c.Deps[m])
		}
		b.WriteString(")\n")
	}
	return os.WriteFile(filepath.Join(dir, "go.mod"), []byte(b.String()), 0o644)
}

func sanitizeFileName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, s)
}
