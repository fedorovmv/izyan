// Package report renders the AnalysisCase into the persisted JSON artifact
// and a human-readable/tracker-ready markdown summary.
package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Write stores report.json and report.md inside dir.
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
		fmt.Fprintf(&b, "## Exploit model\n\nImpact: %s\n\n", c.Exploit.Impact)
		writeConditions(&b, "Mandatory conditions", c.Exploit.MandatoryConditions)
		writeConditions(&b, "Supporting factors", c.Exploit.SupportingFactors)
	}
	if len(c.Claims) > 0 {
		b.WriteString("## Claims\n\n| condition | result | evidence |\n|---|---|---|\n")
		for _, cl := range c.Claims {
			fmt.Fprintf(&b, "| `%s` | %s | %s |\n", cl.ConditionID, cl.Result, strings.Join(evidenceIDs(cl.EvidenceIDs), ", "))
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
		fmt.Fprintf(b, "- `%s` [%s]: %s\n", cond.ID, cond.Kind, cond.Description)
	}
	b.WriteString("\n")
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

func shortCommit(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
