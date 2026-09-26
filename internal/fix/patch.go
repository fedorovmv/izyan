package fix

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Provider fetches the unified diff for a fix reference.
type Provider interface {
	Fetch(ctx context.Context, ref Reference) (string, error)
}

// HTTPProvider resolves patch URLs for common VCS layouts:
//   - github.com/<org>/<repo>/commit/<sha>        -> +".patch"
//   - *.googlesource.com/<repo>/+/<sha>           -> "^!/?format=TEXT" (base64)
//   - URLs already ending in .patch / .diff       -> as-is
type HTTPProvider struct {
	Client  *http.Client
	MaxSize int64 // bytes; default 512 KiB
}

func (p HTTPProvider) Fetch(ctx context.Context, ref Reference) (string, error) {
	u, err := patchURL(ref.URL)
	if err != nil {
		return "", err
	}
	c := p.Client
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	max := p.MaxSize
	if max <= 0 {
		max = 512 << 10
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch patch %s: %w", redact(u), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fetch patch %s: HTTP %d", redact(u), resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return "", err
	}
	if int64(len(body)) > max {
		return "", fmt.Errorf("patch exceeds %d bytes", max)
	}
	if needsBase64(u) {
		dec := make([]byte, base64.StdEncoding.DecodedLen(len(body)))
		n, err := base64.StdEncoding.Decode(dec, bytes.TrimSpace(body))
		if err != nil {
			return "", fmt.Errorf("decode patch body: %w", err)
		}
		return string(dec[:n]), nil
	}
	return string(body), nil
}

func patchURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	switch {
	case strings.HasSuffix(u.Path, ".patch"), strings.HasSuffix(u.Path, ".diff"):
		return raw, nil
	// go.dev/cl/<id> shortlinks resolve to a Gerrit change; the current
	// revision patch is downloadable base64-encoded.
	case (u.Host == "go.dev" || u.Host == "golang.org") && strings.HasPrefix(u.Path, "/cl/"):
		id := strings.Trim(strings.TrimPrefix(u.Path, "/cl/"), "/")
		return "https://go-review.googlesource.com/changes/" + id + "/revisions/current/patch?download", nil
	case strings.Contains(u.Host, "googlesource.com") && strings.Contains(u.Path, "/+/"):
		return strings.TrimSuffix(raw, "/") + "^!/?format=TEXT", nil
	case strings.Contains(u.Path, "/commit/"), strings.Contains(u.Path, "/commits/"):
		u.Path = strings.TrimSuffix(u.Path, "/") + ".patch"
		return u.String(), nil
	}
	return "", fmt.Errorf("unsupported fix reference: %s", redact(raw))
}

// needsBase64 reports whether the response body is base64-encoded
// (googlesource format=TEXT and Gerrit patch?download responses both are).
func needsBase64(raw string) bool {
	return (strings.Contains(raw, "googlesource.com") && strings.Contains(raw, "format=TEXT")) ||
		strings.Contains(raw, "/patch?download")
}

func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparsable url>"
	}
	return u.Host + u.Path
}

// File describes one file touched by a unified diff.
type File struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols,omitempty"` // enclosing function names
	Adds    int      `json:"added_lines"`
	Dels    int      `json:"deleted_lines"`
}

// Patch is a parsed unified diff — the set of files it touches.
type Patch []File

var (
	diffGitRe  = regexp.MustCompile(`^diff --git a/(\S+) b/(\S+)`)
	hunkRe     = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@\s*(.*)`)
	funcCtxRe  = regexp.MustCompile(`func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*\(`)
	funcDeclRe = regexp.MustCompile(`^[+-]?func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*\(`)
)

// Parse splits a unified diff into per-file entries and extracts the names
// of the enclosing functions from hunk headers and changed func decls.
func Parse(patch string) Patch {
	var files Patch
	var cur *File
	var curSym string
	flush := func() {
		if cur != nil {
			files = append(files, *cur)
		}
	}
	for _, line := range strings.Split(patch, "\n") {
		if m := diffGitRe.FindStringSubmatch(line); m != nil {
			flush()
			cur = &File{Path: strings.TrimPrefix(m[2], "b/")}
			curSym = ""
			continue
		}
		if cur == nil {
			continue
		}
		if m := hunkRe.FindStringSubmatch(line); m != nil {
			if fm := funcCtxRe.FindStringSubmatch(m[1]); fm != nil {
				curSym = qualifySym(fm[1], fm[2])
				addSymbol(cur, curSym)
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "+"):
			cur.Adds++
		case strings.HasPrefix(line, "-"):
			cur.Dels++
		}
		if fm := funcDeclRe.FindStringSubmatch(strings.TrimLeft(line, "+-")); fm != nil {
			addSymbol(cur, qualifySym(fm[1], fm[2]))
		}
	}
	flush()
	return files
}

// qualifySym renders a parsed func/method name as "Type.Name" when a
// receiver is present: "func (ch *Channel) recvContent" -> "Channel.recvContent".
// The verifier resolves Type.Method symbols; a bare name would miss methods.
func qualifySym(recv, name string) string {
	if recv == "" {
		return name
	}
	f := strings.Fields(recv)
	if len(f) == 0 {
		return name
	}
	t := strings.TrimPrefix(f[len(f)-1], "*")
	if i := strings.IndexByte(t, '['); i >= 0 {
		t = t[:i] // generic receiver instantiation
	}
	if t == "" {
		return name
	}
	return t + "." + name
}

func addSymbol(f *File, name string) {
	for _, s := range f.Symbols {
		if s == name {
			return
		}
	}
	f.Symbols = append(f.Symbols, name)
}
