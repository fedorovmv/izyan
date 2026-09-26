// Package exposure resolves deployment-level network exposure as
// deterministic facts: which addresses listeners bind, where outbound
// calls into the vulnerable module connect, and which config/env values
// carry those addresses. Facts describe scope, never a verdict.
package exposure

import (
	"bufio"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Item is a key/value pair found in a repository config file.
type Item struct {
	Key   string
	Value string
	File  string
	Line  int
}

var (
	configExtRe = map[string]bool{
		".yaml": true, ".yml": true, ".json": true, ".toml": true,
		".env": true, ".ini": true, ".conf": true, ".properties": true,
	}
	// addrKeyRe matches config keys plausibly carrying network addresses.
	addrKeyRe = regexp.MustCompile(`(?i)(^|[._\-])(listen|bind|addr|address|host|port|dsn|url|uri|endpoint|broker|server)([._\-]|$)`)
	// kvRe splits simple "key: value" / "key=value" lines.
	kvRe = regexp.MustCompile(`^\s*["']?([A-Za-z_][A-Za-z0-9_.\-]*)["']?\s*[:=]\s*["']?([^"'#\n]+?)["']?\s*(?:#.*)?$`)
)

// SkipDirs are never scanned for config facts.
var SkipDirs = map[string]bool{
	"vendor": true, ".git": true, "node_modules": true, "testdata": true,
}

// ScanRepo walks root for config files and returns key/value pairs whose
// keys look network-address-related. Facts are raw: the caller decides
// which keys resolve which exposure source.
func ScanRepo(root string) ([]Item, error) {
	var out []Item
	err := filepath.WalkDir(root, func(path string, e fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if SkipDirs[e.Name()] {
				return fs.SkipDir
			}
			return nil
		}
		if !configExtRe[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if info, err := e.Info(); err != nil || info.Size() > 1<<20 {
			return nil
		}
		items, err := scanFile(path)
		if err != nil {
			return nil
		}
		out = append(out, items...)
		return nil
	})
	return out, err
}

func scanFile(path string) ([]Item, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Item
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		m := kvRe.FindStringSubmatch(sc.Text())
		if m == nil || !addrKeyRe.MatchString(m[1]) {
			continue
		}
		out = append(out, Item{
			Key:   m[1],
			Value: sanitizeValue(strings.TrimSpace(m[2])),
			File:  path,
			Line:  line,
		})
	}
	return out, sc.Err()
}

// sanitizeValue strips userinfo from URL-shaped config values — DSNs and
// broker URLs commonly embed credentials which must not propagate into
// facts, claims or reports.
func sanitizeValue(v string) string {
	i := strings.Index(v, "://")
	if i < 0 {
		return v
	}
	rest := v[i+3:]
	if at := strings.IndexByte(rest, '@'); at >= 0 {
		return v[:i+3] + "***@" + rest[at+1:]
	}
	return v
}

// Lookup finds a config item by key (case-insensitive, exact match on the
// last dotted segment or the whole key).
func Lookup(items []Item, key string) *Item {
	key = strings.ToLower(key)
	for i := range items {
		k := strings.ToLower(items[i].Key)
		last := k
		if j := strings.LastIndexByte(k, '.'); j >= 0 {
			last = k[j+1:]
		}
		if k == key || last == key {
			return &items[i]
		}
	}
	return nil
}

// Scope classifies a resolved inbound bind address.
func Scope(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return domain.ScopeUnknown
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not host:port — maybe a bare port or a unix path.
		if strings.HasPrefix(addr, "/") || strings.HasSuffix(addr, ".sock") {
			return domain.ScopeUnix
		}
		if _, err := net.LookupPort("tcp", strings.TrimPrefix(addr, ":")); err == nil && strings.HasPrefix(addr, ":") {
			return domain.ScopeAllInterfaces
		}
		return domain.ScopeUnknown
	}
	switch strings.ToLower(strings.Trim(host, "[]")) {
	case "", "0.0.0.0", "::":
		return domain.ScopeAllInterfaces
	case "localhost", "127.0.0.1", "::1":
		return domain.ScopeLoopback
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return domain.ScopeLoopback
	}
	return domain.ScopeHostSpecific
}

// OutboundScope classifies how an outbound endpoint's value originates:
// literals and constants are static; env/config/var-sourced values are
// operator-configured.
func OutboundScope(addressSource string) string {
	switch {
	case addressSource == "literal" || addressSource == "const":
		return domain.ScopeStatic
	case strings.HasPrefix(addressSource, "env:") || strings.HasPrefix(addressSource, "config:") ||
		strings.HasPrefix(addressSource, "var:") || strings.HasPrefix(addressSource, "field:"):
		return domain.ScopeConfigured
	default:
		return domain.ScopeUnknown
	}
}
