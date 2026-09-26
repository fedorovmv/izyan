// Package report renders the AnalysisCase into the persisted JSON artifact
// and a human-readable/tracker-ready markdown summary.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/mod/semver"

	"example.com/vuln-analyzer/internal/domain"
)

// Write stores report.json, report.md and openvex.json inside dir.
func Write(dir string, c *domain.AnalysisCase) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	jb, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.json"), jb, 0o644); err != nil {
		return err
	}
	vb, err := OpenVEX(c)
	if err != nil {
		return fmt.Errorf("openvex: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openvex.json"), vb, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "report.md"), []byte(Markdown(c)), 0o644)
}

func Markdown(c *domain.AnalysisCase) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Vulnerability analysis: %s\n\n", c.Vulnerability.ID)
	fmt.Fprintf(&b, "- Case: `%s`\n", c.ID)
	fmt.Fprintf(&b, "- Repository: `%s`\n- Commit: `%s`\n- Go: `%s` (%s/%s)\n\n",
		c.Product.Repository, c.Product.Commit, c.Product.GoVersion, c.Product.GOOS, c.Product.GOARCH)

	if c.Verdict != nil {
		fmt.Fprintf(&b, "## Verdict: `%s`\n\n%s\n\n", c.Verdict.Verdict, c.Verdict.Reason)
	}
	if c.Affected != nil {
		a := c.Affected
		fmt.Fprintf(&b, "## Affected analysis\n\n")
		fmt.Fprintf(&b, "| check | result |\n|---|---|\n")
		fmt.Fprintf(&b, "| module present | %s |\n", a.ModulePresent)
		fmt.Fprintf(&b, "| resolved version | `%s` |\n", a.ResolvedVersion)
		fmt.Fprintf(&b, "| version affected | %s |\n", a.VersionAffected)
		fmt.Fprintf(&b, "| package present | %s |\n", a.PackagePresent)
		fmt.Fprintf(&b, "| build relevant | %s |\n\n", a.BuildRelevant)
	}
	if c.RootCause != nil {
		fmt.Fprintf(&b, "## Root cause: `%s`\n\n", c.RootCause.Status)
		for _, rc := range c.RootCause.RootCauses {
			fmt.Fprintf(&b, "- `%s.%s` (%s) — %s\n", rc.Package, rc.Symbol, rc.Role, rc.Mechanism)
		}
		b.WriteString("\n")
	}
	if c.Exploit != nil {
		fmt.Fprintf(&b, "## Exploit model\n\n")
		if c.Exploit.Class != "" {
			fmt.Fprintf(&b, "Class: `%s`\n\n", c.Exploit.Class)
		}
		fmt.Fprintf(&b, "Impact: %s\n\n", c.Exploit.Impact)
		writeConditions(&b, "Mandatory conditions", c.Exploit.MandatoryConditions)
		writeConditions(&b, "Supporting factors", c.Exploit.SupportingFactors)
	}
	if exps := c.EvidenceGraph.ExposuresList(); len(exps) > 0 {
		b.WriteString("## Exposure facts\n\n")
		for _, f := range exps {
			fmt.Fprintf(&b, "- `%s` %s via `%s`", f.Direction, f.Kind, f.Target)
			if f.Address != "" {
				fmt.Fprintf(&b, " — `%s`", f.Address)
			}
			var meta []string
			if f.AddressSource != "" {
				meta = append(meta, "source: "+f.AddressSource)
			}
			if f.Scope != "" {
				meta = append(meta, "scope: "+f.Scope)
			}
			if len(meta) > 0 {
				fmt.Fprintf(&b, " (%s)", strings.Join(meta, ", "))
			}
			fmt.Fprintf(&b, " — %s:%d\n", f.File, f.Line)
		}
		b.WriteString("\n")
	}
	if len(c.Claims) > 0 {
		b.WriteString("## Claims\n\n| condition | result | evidence |\n|---|---|---|\n")
		for _, cl := range c.Claims {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", cl.ConditionID, cl.Result, strings.Join(evidenceIDs(cl.EvidenceIDs), ", "))
		}
		b.WriteString("\n")
	}
	if len(c.Hypotheses) > 0 {
		b.WriteString("## Hypotheses\n\n")
		for _, h := range c.Hypotheses {
			fmt.Fprintf(&b, "- `%s` %s → **%s**: %s", h.ID, h.ConditionID, h.Status, h.Statement)
			if h.Notes != "" {
				fmt.Fprintf(&b, " — %s", h.Notes)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(c.Reviews) > 0 {
		b.WriteString("## Review\n\n")
		for _, rv := range c.Reviews {
			fmt.Fprintf(&b, "- `%s` → **%s**", rv.ID, rv.Result)
			if len(rv.Findings) > 0 {
				b.WriteString("\n")
				for _, f := range rv.Findings {
					fmt.Fprintf(&b, "  - [%s] %s `%s`: %s\n", f.Severity, f.TargetType, f.TargetID, f.Problem)
				}
			} else {
				b.WriteString(" — no findings\n")
			}
		}
		b.WriteString("\n")
	}
	if r := remediation(c); r != "" {
		fmt.Fprintf(&b, "## Remediation\n\n%s\n\n", r)
	}
	if texs := c.EvidenceGraph.ToolExecutions; len(texs) > 0 {
		b.WriteString("## Tool executions\n\n| tool | args | exit | ms | stdout sha256 |\n|---|---|---|---|---|\n")
		for _, t := range texs {
			tool := t.Tool
			if t.Version != "" {
				tool += "@" + t.Version
			}
			hash := t.StdoutSHA256
			if len(hash) > 12 {
				hash = hash[:12] + "…"
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %d | %d | `%s` |\n",
				tool, strings.Join(t.Args, " "), t.ExitCode, t.DurationMs, hash)
		}
		b.WriteString("\n")
	}
	if lims := allLimitations(c); len(lims) > 0 {
		b.WriteString("## Limitations\n\n")
		for _, l := range lims {
			fmt.Fprintf(&b, "- %s\n", l)
		}
	}
	fmt.Fprintf(&b, "\n## Tracker-ready rationale\n\n%s\n", rationale(c))
	return b.String()
}

func writeConditions(b *strings.Builder, title string, conds []domain.Condition) {
	if len(conds) == 0 {
		return
	}
	fmt.Fprintf(b, "### %s\n\n", title)
	for _, cond := range conds {
		fmt.Fprintf(b, "- `%s` [%s]: %s%s\n", cond.ID, cond.Kind, cond.Description, renderParams(cond.Params))
	}
	b.WriteString("\n")
}

func renderParams(params map[string]string) string {
	if len(params) == 0 {
		return ""
	}
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+params[k])
	}
	return " {" + strings.Join(parts, ", ") + "}"
}

func evidenceIDs(ids []domain.EvidenceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

func allLimitations(c *domain.AnalysisCase) []string {
	var out []string
	if c.Affected != nil {
		out = append(out, c.Affected.Limitations...)
	}
	if c.RootCause != nil {
		out = append(out, c.RootCause.Limitations...)
	}
	out = append(out, c.EvidenceGraph.Limitations...)
	out = append(out, c.EvidenceGraph.ToolLimitations...)
	if c.Verdict != nil {
		out = append(out, c.Verdict.Limitations...)
	}
	return out
}

func rationale(c *domain.AnalysisCase) string {
	if c.Verdict == nil {
		return "analysis did not reach a verdict"
	}
	switch c.Verdict.Verdict {
	case domain.VerdictNotAffected:
		return fmt.Sprintf("%s is NOT_AFFECTED for %s@%s: %s. No code changes required for this snapshot.",
			c.Vulnerability.ID, c.Product.Repository, shortCommit(c.Product.Commit), c.Verdict.Reason)
	case domain.VerdictExploitable:
		return fmt.Sprintf("%s is EXPLOITABLE in %s@%s: %s. Remediation required.",
			c.Vulnerability.ID, c.Product.Repository, shortCommit(c.Product.Commit), c.Verdict.Reason)
	case domain.VerdictNoExploitPathFound:
		return fmt.Sprintf("%s has NO_EXPLOIT_PATH_FOUND in %s@%s: %s.",
			c.Vulnerability.ID, c.Product.Repository, shortCommit(c.Product.Commit), c.Verdict.Reason)
	default:
		return fmt.Sprintf("%s analysis is INCONCLUSIVE for %s@%s: %s. Manual review required.",
			c.Vulnerability.ID, c.Product.Repository, shortCommit(c.Product.Commit), c.Verdict.Reason)
	}
}

// remediation renders a deterministic fix recommendation: the smallest
// fixed version above the resolved one, plus the go command to apply it.
// Empty when the component is not affected or no fix is published.
func remediation(c *domain.AnalysisCase) string {
	if c.Affected == nil || c.Affected.VersionAffected != domain.ClaimTrue {
		return ""
	}
	mod := c.Vulnerability.Module
	if mod == "" && len(c.Vulnerability.AffectedPackages) > 0 {
		mod = c.Vulnerability.AffectedPackages[0].Path
	}
	if mod == "" {
		return ""
	}
	resolved := c.Affected.ResolvedVersion
	var best string
	for _, f := range c.Vulnerability.FixedVersions {
		fv := normalizeSemver(f)
		if fv == "" {
			continue
		}
		if resolved != "" && semver.Compare(fv, normalizeSemver(resolved)) <= 0 {
			continue
		}
		if best == "" || semver.Compare(fv, best) < 0 {
			best = fv
		}
	}
	if best == "" {
		return fmt.Sprintf("No fixed version published for `%s` (current: `%s`). "+
			"Consider pinning an unaffected release or vendoring a patch.", mod, resolved)
	}
	return fmt.Sprintf("Update `%s` from `%s` to `%s`:\n\n```\ngo get %s@%s\ngo mod tidy\n```",
		mod, resolved, best, mod, best)
}

// normalizeSemver maps "1.2.3"/"v1.2.3" onto canonical semver for compare.
func normalizeSemver(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		v = "v" + v
	}
	if !semver.IsValid(v) {
		return ""
	}
	return v
}

func shortCommit(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
