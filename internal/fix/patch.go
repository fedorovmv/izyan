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
//   - github.com/<org>/<repo>/pull/<n>            -> +".diff" (aggregate diff)
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
	case u.Host == "github.com" && strings.Contains(u.Path, "/pull/"):
		// Pull-request references carry the aggregate diff at .diff; the
		// .patch variant is per-commit mbox noise.
		return strings.TrimSuffix(raw, "/") + ".diff", nil
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
	// GuardedSymbols names functions whose hunk adds a guard (length/nil
	// check) over an operand that unchanged or removed lines of the same
	// hunk then use in a faulting position (index, dereference, call) —
	// the signature of a fix applied at the defect site itself, as
	// opposed to upstream validation (enabler) where the guarded value
	// is only rejected, never consumed unsafely.
	GuardedSymbols []string `json:"guarded_symbols,omitempty"`
	// GuardOperands maps each function to the operand expressions its
	// added guards check — whether or not a faulting use was visible in
	// hunk context. Callers verifying an enabler classification need the
	// operand to rescan the full function body.
	GuardOperands map[string][]string `json:"guard_operands,omitempty"`
	Adds          int                 `json:"added_lines"`
	Dels          int                 `json:"deleted_lines"`
}

// Patch is a parsed unified diff — the set of files it touches.
type Patch []File

var (
	diffGitRe  = regexp.MustCompile(`^diff --git a/(\S+) b/(\S+)`)
	hunkRe     = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@\s*(.*)`)
	funcCtxRe  = regexp.MustCompile(`func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*\(`)
	funcDeclRe = regexp.MustCompile(`^[+-]?func\s+(?:\(([^)]*)\)\s*)?([A-Za-z_]\w*)\s*\(`)
	// guardLenRe matches added bound checks: `if len(x) == 0`,
	// `if len(x) < 4`, ... The operand captured inside len() is the value
	// whose unsafe use the guard protects.
	guardLenRe = regexp.MustCompile(`if\s+len\(([^()]*(?:\([^)]*\)[^()]*)?)\)\s*(?:==|!=|<=?|>=?)\s*\d+`)
	// guardNilRe matches `if x == nil` / `if x != nil` on a simple operand.
	guardNilRe = regexp.MustCompile(`if\s+([A-Za-z_][\w.]*)\s*(?:==|!=)\s*nil`)
)

// hunk accumulates one diff hunk's lines so guard detection can correlate
// an added check with the operand's surviving (or removed) unsafe use.
type hunk struct {
	symbol string
	// guards are the operand expressions guarded by added lines, recorded
	// under the function symbol active when each guard line was seen.
	guards map[string][]string
	uses   []string // all content lines ('+', ' ', '-'), guard lines included
}

// Parse splits a unified diff into per-file entries and extracts the names
// of the enclosing functions from hunk headers and changed func decls.
func Parse(patch string) Patch {
	var files Patch
	var cur *File
	var hk *hunk
	flushHunk := func() {
		if hk != nil {
			markGuardedSite(cur, *hk)
			hk = nil
		}
	}
	flush := func() {
		flushHunk()
		if cur != nil {
			files = append(files, *cur)
		}
	}
	for _, line := range strings.Split(patch, "\n") {
		if m := diffGitRe.FindStringSubmatch(line); m != nil {
			flush()
			cur = &File{Path: strings.TrimPrefix(m[2], "b/")}
			continue
		}
		if cur == nil {
			continue
		}
		if m := hunkRe.FindStringSubmatch(line); m != nil {
			flushHunk()
			hk = &hunk{}
			if fm := funcCtxRe.FindStringSubmatch(m[1]); fm != nil {
				hk.symbol = qualifySym(fm[1], fm[2])
				addSymbol(cur, hk.symbol)
			}
			continue
		}
		switch {
		case strings.HasPrefix(line, "+"):
			cur.Adds++
			if hk != nil {
				body := line[1:]
				if ops := guardOperands(body); len(ops) > 0 && hk.symbol != "" {
					if hk.guards == nil {
						hk.guards = map[string][]string{}
					}
					hk.guards[hk.symbol] = append(hk.guards[hk.symbol], ops...)
				}
				hk.uses = append(hk.uses, body)
			}
		case strings.HasPrefix(line, "-"):
			cur.Dels++
			if hk != nil {
				hk.uses = append(hk.uses, line[1:])
			}
		case strings.HasPrefix(line, " "):
			if hk != nil {
				hk.uses = append(hk.uses, line[1:])
			}
		}
		if fm := funcDeclRe.FindStringSubmatch(strings.TrimLeft(line, "+-")); fm != nil {
			sym := qualifySym(fm[1], fm[2])
			if hk != nil {
				hk.symbol = sym
			}
			addSymbol(cur, sym)
		}
	}
	flush()
	return files
}

// markGuardedSite flags the hunk's function when an added guard protects a
// value that the same hunk's surviving, removed or added lines use
// unsafely — `len(x) == 0` before `x[i]`, `x == nil` before `x.f`/`x(...)`.
// The correlation is positional evidence that the check sits at the defect
// site rather than at an upstream validation point. All guard operands are
// recorded regardless so callers can verify the enabler classification
// against the full function body.
func markGuardedSite(f *File, hk hunk) {
	if f == nil {
		return
	}
	for sym, operands := range hk.guards {
		if f.GuardOperands == nil {
			f.GuardOperands = map[string][]string{}
		}
		f.GuardOperands[sym] = append(f.GuardOperands[sym], operands...)
		for _, operand := range operands {
			for _, use := range hk.uses {
				if faultingUse(use, operand) {
					addGuardedSymbol(f, sym)
					break
				}
			}
		}
	}
}

// guardOperands extracts the guarded value from an added guard line.
// `if len(x) == 0` guards `x` against indexing; `if x == nil`/`!= nil`
// guards `x` against dereference. Generic error checks (`err != nil`) are
// skipped as standard control flow rather than vulnerability guards.
func guardOperands(line string) []string {
	var out []string
	if m := guardLenRe.FindStringSubmatch(line); m != nil {
		if op := strings.TrimSpace(m[1]); op != "" && !isGenericOperand(op) {
			out = append(out, op)
		}
	}
	if m := guardNilRe.FindStringSubmatch(line); m != nil {
		if op := strings.TrimSpace(m[1]); op != "" && !isGenericOperand(op) {
			out = append(out, op)
		}
	}
	return out
}

func isGenericOperand(op string) bool {
	switch op {
	case "err", "error":
		return true
	}
	return false
}

// faultingUse reports whether line uses operand in a position that can
// fault when the guarded property does not hold: `x[...]` indexes a
// possibly empty slice, `x.f`/`x(...)` dereferences a possibly nil value.
// For a len-guarded operand an index expression is the fault; any direct
// use of a nil-guarded operand is.
func faultingUse(line, operand string) bool {
	idx := regexp.QuoteMeta(operand)
	indexRe := regexp.MustCompile(`(?:^|[^\w.\]])` + idx + `\s*\[`)
	if indexRe.MatchString(line) {
		return true
	}
	derefRe := regexp.MustCompile(`(?:^|[^\w.\]])` + idx + `\s*(?:\.|\()`)
	return derefRe.MatchString(line)
}

func addGuardedSymbol(f *File, name string) {
	for _, s := range f.GuardedSymbols {
		if s == name {
			return
		}
	}
	f.GuardedSymbols = append(f.GuardedSymbols, name)
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
