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

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
)

// Write stores report.json, report.md, openvex.json and cyclonedx.json
// inside dir.
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
	cb, err := CycloneDX(c)
	if err != nil {
		return fmt.Errorf("cyclonedx: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cyclonedx.json"), cb, 0o644); err != nil {
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
		fmt.Fprintf(&b, "| build relevant | %s |\n", a.BuildRelevant)
		if len(a.CheckedModules) > 0 {
			fmt.Fprintf(&b, "| modules probed | `%s` |\n", strings.Join(a.CheckedModules, "`, `"))
		}
		if len(a.SelectedModules) > 0 {
			fmt.Fprintf(&b, "| modules linked | `%s` |\n", strings.Join(a.SelectedModules, "`, `"))
		}
		if len(a.PendingModules) > 0 {
			fmt.Fprintf(&b, "| modules version-unresolved | `%s` |\n", strings.Join(a.PendingModules, "`, `"))
		}
		if len(a.CheckedPackages) > 0 {
			fmt.Fprintf(&b, "| packages probed | `%s` |\n", strings.Join(a.CheckedPackages, "`, `"))
		}
		if len(a.EvidenceIDs) > 0 {
			fmt.Fprintf(&b, "| evidence | %s |\n", strings.Join(evidenceIDs(a.EvidenceIDs), ", "))
		}
		b.WriteString("\n")
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
		if len(c.Exploit.NonLocusBasis) > 0 {
			b.WriteString("### Экспертные решения `non_locus` — исключённые символы\n\n")
			b.WriteString("Покрытие опровержения сужено этими записанными экспертом исключениями — зафиксированное основание, не машинные данные:\n\n")
			for _, d := range c.Exploit.NonLocusBasis {
				auth := d.Authority
				if auth == "" {
					auth = "expert"
				}
				fmt.Fprintf(&b, "- `%s.%s` — %s (%s)\n", d.Symbol.Package, d.Symbol.Symbol, d.Basis, auth)
			}
			b.WriteString("\n")
		}
		if len(c.Exploit.ProposedNonLocus) > 0 || len(c.Exploit.LocusSubjects) > 0 {
			b.WriteString("### Машинная оценка — предложение, не вердикт\n\n")
			b.WriteString(machineAssessment(c))
			b.WriteString("\n")
		}
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
	if len(c.EvidenceGraph.DataFlows) > 0 {
		b.WriteString("## Data flows\n\n")
		for _, f := range c.EvidenceGraph.DataFlows {
			var tx []string
			for _, t := range f.Transformations {
				tx = append(tx, t.Callee)
			}
			fmt.Fprintf(&b, "- `%s` %s", f.Origin, f.Summary)
			if len(tx) > 0 {
				fmt.Fprintf(&b, " — via `%s`", strings.Join(tx, "`, `"))
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if len(c.EvidenceGraph.Runtime) > 0 {
		b.WriteString("## Runtime facts\n\n")
		for _, id := range c.EvidenceGraph.Runtime {
			if e := c.EvidenceGraph.EvidenceByID(id); e != nil {
				fmt.Fprintf(&b, "- %s: %s\n\n", e.Source, e.Content)
			}
		}
	}
	var bt []domain.Evidence
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind == domain.EvidenceBuild || e.Kind == domain.EvidenceTest {
			bt = append(bt, e)
		}
	}
	if len(bt) > 0 {
		b.WriteString("## Build & test\n\n")
		for _, e := range bt {
			name := e.Command
			if name == "" {
				name = e.Source
			}
			status := e.Content
			if i := strings.IndexByte(status, '\n'); i >= 0 {
				status = status[:i]
			}
			fmt.Fprintf(&b, "- `%s` — %s\n", name, status)
		}
		b.WriteString("\n")
	}
	if len(c.Claims) > 0 {
		b.WriteString("## Claims\n\n| condition | result | verification | evidence |\n|---|---|---|---|\n")
		for _, cl := range c.Claims {
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", cl.ConditionID, cl.Result,
				claimVerification(cl), strings.Join(evidenceIDs(cl.EvidenceIDs), ", "))
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

// claimVerification renders the falsifier/NV status so a claim that was
// proven and then demoted by review stays auditable in the table —
// e.g. "guards / VERIFIED (demoted)" instead of a bare UNKNOWN.
func claimVerification(cl domain.Claim) string {
	if cl.NegativeVerification == nil && cl.Falsifier == "" {
		return ""
	}
	var s string
	if cl.Falsifier != "" {
		s = string(cl.Falsifier)
	}
	if cl.NegativeVerification != nil {
		if s != "" {
			s += " / "
		}
		s += string(cl.NegativeVerification.Status)
	}
	if cl.Result == domain.ClaimUnknown && cl.NegativeVerification != nil &&
		cl.NegativeVerification.Status == domain.NegativeVerified {
		s += " (demoted)"
	}
	return s
}

func evidenceIDs(ids []domain.EvidenceID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = string(id)
	}
	return out
}

// machineAssessment renders the case-level machine opinion: a proposed
// disposition for the defect-locus falsifier, the expert decisions it
// depends on, and the assumptions outside machine verification. The
// package-absent falsifier needs every locus subject in a linked package
// to carry a recorded expert exclusion — so the block lists, per declared
// symbol, its package status and what the expert still has to decide.
// Advisory text for review — never part of the verdict.
func machineAssessment(c *domain.AnalysisCase) string {
	if c.Exploit == nil || len(c.Exploit.LocusSubjects) == 0 {
		return ""
	}
	proposed := map[domain.SymbolRef]domain.LocusDecision{}
	for _, d := range c.Exploit.ProposedNonLocus {
		proposed[d.Symbol] = d
	}
	annotated := map[domain.SymbolRef]domain.LocusDecision{}
	for _, d := range c.Exploit.LocusAnnotations {
		annotated[d.Symbol] = d
	}

	var set map[string]bool
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if e.Kind != domain.EvidencePackageList {
			continue
		}
		if s, err := affected.PackageImportPaths([]byte(e.Content)); err == nil {
			set = s
		}
		break
	}
	if set == nil {
		return "Оценку «отсутствие пакета» выставить нельзя: нет декодируемого списка пакетов `go list -deps`.\n"
	}

	var b strings.Builder
	b.WriteString("Опровержение через отсутствие пакета применимо, только если по каждому символу сайта дефекта в *присутствующем в сборке* пакете записано экспертное решение `non_locus`:\n\n")
	var pending, proposedN, flagged int
	for _, s := range c.Exploit.LocusSubjects {
		name := "`" + s.Package + "." + s.Symbol + "`"
		if !set[s.Package] {
			fmt.Fprintf(&b, "- %s — пакет **отсутствует** в `go list -deps` — покрыт опровержением\n", name)
			continue
		}
		pending++
		if d, ok := proposed[s]; ok {
			proposedN++
			fmt.Fprintf(&b, "- %s — пакет присутствует в сборке — машина **предлагает** исключение: %s\n", name, d.Basis)
			continue
		}
		if d, ok := annotated[s]; ok {
			flagged++
			fmt.Fprintf(&b, "- %s — пакет присутствует в сборке — **не предлагается**: машинная аннотация `%s` — исключение означает, что эксперт опровергает этот флаг\n", name, d.Basis)
		} else {
			fmt.Fprintf(&b, "- %s — пакет присутствует в сборке — **не предлагается**, машинной аннотации нет — нужно решение эксперта\n", name)
		}
	}
	b.WriteString("\n")
	switch {
	case pending == 0:
		b.WriteString("**Предлагаемая оценка: ОТКЛОНИТЬ** — все пакеты сайта дефекта отсутствуют в графе сборки; опровержение выполнено само по себе.\n")
	case flagged == 0 && pending == proposedN:
		fmt.Fprintf(&b,
			"**Предлагаемая оценка: ОТКЛОНИТЬ после утверждения** — запишите %d машинных предложения как `non_locus` — оставшиеся пакеты сайта дефекта все отсутствуют → `NO_EXPLOIT_PATH_FOUND`.\n",
			pending)
	case flagged == 0:
		fmt.Fprintf(&b,
			"**Предлагаемая оценка: УСЛОВНО** — для отклонения нужны записанные решения `non_locus` по всем %d символам в присутствующих пакетах выше (%d уже предложены машиной, %d без аннотации — машина по ним ничего не знает).\n",
			pending, proposedN, pending-proposedN)
	default:
		fmt.Fprintf(&b,
			"**Предлагаемая оценка: УСЛОВНО** — для отклонения нужны записанные решения `non_locus` по всем %d символам в присутствующих пакетах выше (%d предложены машиной); %d несут машинный флаг «возможный сайт дефекта», который эксперт должен опровергнуть.\n",
			pending, proposedN, flagged)
	}
	b.WriteString("\nВне машинной проверки (допущения, которые ревьюер принимает при утверждении):\n")
	b.WriteString("- объявленное advisory множество символов полно — сайт дефекта вне объявленных символов этому контракту невидим\n")
	b.WriteString("- записанные экспертные решения истинны — опровержение проверяет их покрытие, а не корректность\n")
	goos, goarch := c.Product.GOOS, c.Product.GOARCH
	if goos == "" {
		goos = "?"
	}
	if goarch == "" {
		goarch = "?"
	}
	tags := strings.Join(c.Product.BuildTags, ", ")
	if tags == "" {
		tags = "не записаны"
	}
	fmt.Fprintf(&b, "- записанный контекст сборки (%s/%s, теги: %s) соответствует конфигурации развёртывания\n",
		goos, goarch, tags)
	return b.String()
}

func allLimitations(c *domain.AnalysisCase) []string {
	var out []string
	add := func(l string) {
		for _, x := range out {
			if x == l {
				return
			}
		}
		out = append(out, l)
	}
	if c.Affected != nil {
		for _, l := range c.Affected.Limitations {
			add(l)
		}
	}
	if c.RootCause != nil {
		for _, l := range c.RootCause.Limitations {
			add(l)
		}
	}
	// The verdict copies graph limitations into its own record — dedupe,
	// or every limitation prints twice.
	for _, l := range c.EvidenceGraph.Limitations {
		add(l)
	}
	for _, l := range c.EvidenceGraph.ToolLimitations {
		add(l)
	}
	if c.Verdict != nil {
		for _, l := range c.Verdict.Limitations {
			add(l)
		}
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

// FixTarget picks the smallest published fixed version above the
// resolved one. ok=false when the component is not affected or the
// module cannot be named; version="" with ok=true means no fix exists.
func FixTarget(c *domain.AnalysisCase) (module, version string, ok bool) {
	if c.Affected == nil || c.Affected.VersionAffected != domain.ClaimTrue {
		return "", "", false
	}
	mod := c.Vulnerability.Module
	if mod == "" && len(c.Vulnerability.AffectedPackages) > 0 {
		mod = c.Vulnerability.AffectedPackages[0].Path
	}
	if mod == "" {
		return "", "", false
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
	return mod, best, true
}

// remediation renders a deterministic fix recommendation: the smallest
// fixed version above the resolved one, plus the go command to apply it.
// Empty when the component is not affected or no fix is published.
func remediation(c *domain.AnalysisCase) string {
	mod, best, ok := FixTarget(c)
	if !ok {
		return ""
	}
	resolved := c.Affected.ResolvedVersion
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
