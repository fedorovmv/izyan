package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/evaluator"
	"example.com/vuln-analyzer/internal/exploit"
	"example.com/vuln-analyzer/internal/fix"
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/llm"
	"example.com/vuln-analyzer/internal/persistence/filesystem"
	"example.com/vuln-analyzer/internal/repository"
	"example.com/vuln-analyzer/internal/review"
	"example.com/vuln-analyzer/internal/rootcause"
	"example.com/vuln-analyzer/internal/states"
	"example.com/vuln-analyzer/internal/toolaudit"
	"example.com/vuln-analyzer/internal/toolchain"
	"example.com/vuln-analyzer/internal/tracker"
	"example.com/vuln-analyzer/internal/vulnerability"
	"example.com/vuln-analyzer/internal/workflow"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "analyze":
		err = runAnalyze(os.Args[2:])
	case "scan":
		err = runScan(os.Args[2:])
	case "eval":
		err = runEval(os.Args[2:])
	case "remediate":
		err = runRemediate(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  vuln-analyzer analyze --repo <path> --vuln <GO-/CVE-/GHSA-id> [options]
  vuln-analyzer scan    --repo <path> [options]   # all advisories for all modules
  vuln-analyzer eval    --corpus <path> --repo <path> [options]  # corpus regression run
  vuln-analyzer remediate --repo <path> --vuln <id> [--apply] [--run-tests]  # plan/apply fix + re-analyze

options:
  --vuln-file <path>     load advisory from local OSV JSON instead of api.osv.dev
  --ticket <path>        generic tracker ticket JSON (see internal/tracker/intake.go)
  --osv-url <url>        override OSV API base URL
  --case-dir <dir>       analysis state directory (default .vuln-analyzer)
  --goos/--goarch        target platform (default: host)
  --build-tags a,b       build tags
  --root-cause p.Sym     manual root cause symbol (repeatable, comma-separated)
  --exploit-model <path> manual exploit model JSON
  --deterministic-only   disable all LLM-backed states`)
	os.Exit(2)
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

type analyzeOpts struct {
	repo          string
	vulnID        string
	vulnFile      string
	osvURL        string
	caseDir       string
	goos          string
	goarch        string
	tags          string
	binary        string
	releaseGo     string
	exploitModel  string
	llmEnv        string
	detOnly       bool
	allowExec     bool
	rootCauseArgs []string
	// manualRC carries already-parsed root causes (eval corpus entries
	// support the object form, which rootCauseArgs strings cannot express).
	manualRC []domain.RootCause
	// toolchain is the resolved target Go toolchain; zero value = local.
	toolchain toolchain.Toolchain
	// tcLims carries resolution notes into the case's limitations.
	tcLims []string
	// Shared across advisories in scan mode; nil in single analyze.
	srcIndex *goanalysis.Index
	goTool   affected.GoTool
	gvRunner goanalysis.Runner
}

// commonFlags registers the flags shared by analyze and scan.
func commonFlags(fs *flag.FlagSet, o *analyzeOpts) {
	fs.StringVar(&o.repo, "repo", "", "path to Go repository")
	fs.StringVar(&o.osvURL, "osv-url", "", "OSV API base URL")
	fs.StringVar(&o.caseDir, "case-dir", ".vuln-analyzer", "case state directory")
	fs.StringVar(&o.goos, "goos", "", "target GOOS")
	fs.StringVar(&o.goarch, "goarch", "", "target GOARCH")
	fs.StringVar(&o.tags, "build-tags", "", "comma-separated build tags")
	fs.StringVar(&o.binary, "binary", "", "release-built Go binary: govulncheck -mode binary + embedded toolchain")
	fs.StringVar(&o.releaseGo, "release-go-version", "", "toolchain version that built the release (e.g. from the ticket)")
	fs.BoolVar(&o.detOnly, "deterministic-only", false, "disable LLM-backed states")
	fs.BoolVar(&o.allowExec, "allow-exec", false, "permit agent tools that execute repository code (run_build/run_tests)")
	fs.StringVar(&o.llmEnv, "llm-env", "", "path to LLM .env file (default: .env in cwd or repo)")
}

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	fs.StringVar(&o.vulnID, "vuln", "", "vulnerability id (GO-/CVE-/GHSA-)")
	fs.StringVar(&o.vulnFile, "vuln-file", "", "local OSV JSON file")
	fs.StringVar(&o.exploitModel, "exploit-model", "", "manual exploit model JSON")
	ticketPath := fs.String("ticket", "", "generic tracker ticket JSON (vulnerability id, repo, embedded/synthesized advisory)")
	var rootCauseFlags stringList
	fs.Var(&rootCauseFlags, "root-cause", "manual root cause as pkg/path.Symbol (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.rootCauseArgs = rootCauseFlags
	if *ticketPath != "" {
		if err := applyTicket(&o, *ticketPath); err != nil {
			return err
		}
	}
	if o.repo == "" || o.vulnID == "" {
		usage()
	}
	c, err := analyzeCase(context.Background(), o)
	if err != nil {
		return err
	}
	printCase(c, o.caseDir)
	return nil
}

// applyTicket folds a generic tracker ticket into analyze options:
// explicit CLI flags win over ticket fields (ticket is the default, not
// an override). Advisory material (embedded osv doc, or module +
// fixed_versions) is materialized to a file and fed via --vuln-file.
func applyTicket(o *analyzeOpts, path string) error {
	t, err := tracker.LoadTicket(path)
	if err != nil {
		return err
	}
	if o.vulnID == "" {
		o.vulnID = t.Vulnerability
	}
	if o.repo == "" && t.Repo != "" {
		o.repo = t.Repo
	}
	if o.vulnFile == "" && (len(t.OSV) > 0 || t.Module != "") {
		dir := filepath.Join(o.caseDir, "intake")
		f, err := t.AdvisoryFile(dir, o.vulnID)
		if err != nil {
			return fmt.Errorf("ticket advisory: %w", err)
		}
		if f != "" {
			o.vulnFile = f
		}
	}
	return nil
}

// analyzeCase runs the full pipeline for one vulnerability id.
func analyzeCase(ctx context.Context, o analyzeOpts) (*domain.AnalysisCase, error) {
	absRepo, err := filepath.Abs(o.repo)
	if err != nil {
		return nil, err
	}

	var src vulnerability.Source
	if o.vulnFile != "" {
		src = vulnerability.FileSource{Path: o.vulnFile}
	} else {
		src = vulnerability.OSVSource{BaseURL: o.osvURL}
	}

	store := filesystem.New(o.caseDir)
	prior := store.PriorCase(ctx, o.vulnID, absRepo, "")
	caseID := domain.CaseID(fmt.Sprintf("%s-%d", sanitizeID(o.vulnID), time.Now().Unix()))
	c := &domain.AnalysisCase{
		ID: caseID,
		Workflow: domain.WorkflowStatus{
			State:     domain.StateCreated,
			StartedAt: time.Now().UTC(),
			UpdatedAt: time.Now().UTC(),
			Limits: domain.AnalysisLimits{
				MaxIterations:       64,
				MaxToolCalls:        128,
				MaxLLMCalls:         32,
				MaxSourceReads:      256,
				MaxReviewIterations: 2,
			},
		},
	}
	c.EvidenceGraph.Version = "1"
	if prior != nil {
		c.PriorCase = prior.ID
	}
	if err := store.Create(ctx, c); err != nil {
		return nil, err
	}
	// Every external tool run under this ctx lands in the case's audit
	// trail — including toolchain probes and the product snapshot below.
	ctx = toolaudit.WithRecorder(ctx, &toolaudit.Recorder{Sink: c.EvidenceGraph.AddToolExecution})

	tc := o.toolchain
	if tc.GoBin == "" {
		var lims []string
		tc, lims = resolveToolchain(ctx, o)
		o.tcLims = lims
	}
	for _, l := range o.tcLims {
		c.EvidenceGraph.AddLimitation(l)
	}
	c.EvidenceGraph.AddLimitation(fmt.Sprintf(
		"analysis toolchain: go%s (%s)", tc.Version, tc.Mode))

	srcIndex := o.srcIndex
	if srcIndex == nil {
		srcIndex = &goanalysis.Index{
			Dir: absRepo,
			Env: tc.Env,
			Build: domain.ProductSnapshot{
				GOOS: o.goos, GOARCH: o.goarch, BuildTags: splitCSV(o.tags),
			},
		}
	}
	goTool := o.goTool
	if goTool == nil {
		goTool = affected.ExecGoTool{Bin: tc.GoBin, Env: tc.Env, Version: tc.Version}
	}
	gvRunner := o.gvRunner
	if gvRunner == nil {
		gvRunner = goanalysis.ExecRunner{Env: tc.Env}
	}

	// LLM layer: env file auto-load (explicit --llm-env, else .env in
	// cwd or repo). LLM adapters only propose; verification stays
	// deterministic. Without LLM_ENABLED the pure deterministic path runs.
	loadLLMEnv(o.llmEnv, absRepo)
	llmCfg := llm.ConfigFromEnv()
	var rcResolver states.RootCauseResolver = &rootcause.Resolver{Fix: fix.Resolver{}, Patch: fix.HTTPProvider{}}
	var builder states.ExploitBuilder = &exploit.Builder{Source: srcIndex}
	reviewers := review.Multi{review.Structural{}}
	// The deterministic evaluator chain — shared by EVALUATE_CONDITIONS
	// and the gap-analysis loop's re-evaluation pass.
	conditionEvaluators := []evaluator.ConditionEvaluator{
		evaluator.SymbolReachable{},
		evaluator.ServerTransportInput{},
		evaluator.ArgumentOrigin{},
		evaluator.Validation{},
		evaluator.Exposure{},
		evaluator.Authentication{},
		evaluator.ConfigFlag{},
		evaluator.Presence{},
		evaluator.VersionFact{},
		evaluator.Platform{},
	}
	var fallbackEval evaluator.ConditionEvaluator
	var gapPlanner states.HypothesisPlanner
	if llmCfg.Enabled && !o.detOnly {
		client := llm.NewClient(llmCfg)
		tools := llm.Tools{
			Source:      srcIndex,
			Vuln:        src,
			Patch:       fix.HTTPProvider{},
			Govulncheck: gvRunner,
			GoTool:      goTool,
			AllowExec:   o.allowExec,
		}
		rcResolver = &llm.RootCauseResolver{Client: client, Fallback: rcResolver}
		builder = llm.ExploitModelBuilder{Client: client, Fallback: builder}
		reviewers = append(reviewers, llm.Reviewer{Client: client})
		fallbackEval = llm.ClaimEvaluator{Client: client, Tools: tools}
		gapPlanner = llm.Planner{Client: client, Tools: tools}
	} else if o.detOnly {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			"deterministic-only mode: LLM adapters disabled")
	} else if llmCfg.BaseURL != "" {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			"llm configured but LLM_ENABLED is off")
	}

	engine := workflow.New(store,
		states.Created{},
		states.SnapshotProduct{
			Repo: repository.Service{},
			Path: absRepo,
			Options: repository.SnapshotOptions{
				GOOS:             o.goos,
				GOARCH:           o.goarch,
				BuildTags:        splitCSV(o.tags),
				BinaryPath:       o.binary,
				ReleaseGoVersion: o.releaseGo,
			},
		},
		states.ResolveVulnerability{Source: src, ID: o.vulnID},
		states.CheckAffected{Resolver: affected.GoResolver{Tool: goTool}},
		states.ResolveRootCause{
			Manual:   append(o.manualRC, parseRootCauses(o.rootCauseArgs)...),
			Resolver: rcResolver,
			Verifier: &rootcause.Verifier{Source: srcIndex},
		},
		states.BuildExploitModel{
			ModelPath: o.exploitModel,
			Builder:   builder,
		},
		states.CollectEvidence{
			Govulncheck: gvRunner,
			Source:      srcIndex,
			OSVBase:     o.osvURL,
		},
		states.EvaluateConditions{Evaluators: conditionEvaluators},
		states.GapAnalysis{Source: srcIndex, Evaluators: conditionEvaluators, Planner: gapPlanner, Fallback: fallbackEval},
		states.NegativeCheck{Verifier: &goanalysis.Verifier{Source: srcIndex}},
		states.Review{Reviewer: reviewers, Evaluator: evaluator.VerdictEvaluator{}},
		states.RepairAnalysis{},
		states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}},
		states.BuildReport{Dir: filepath.Join(o.caseDir, string(caseID)),
			Tracker: tracker.FileSink{Dir: filepath.Join(o.caseDir, string(caseID))},
			Prior:   prior},
	)

	if err := engine.Run(ctx, c); err != nil {
		return c, fmt.Errorf("workflow: %w", err)
	}
	return c, nil
}

func printCase(c *domain.AnalysisCase, caseDir string) {
	fmt.Printf("case: %s\nstate: %s\n", c.ID, c.Workflow.State)
	if c.Verdict != nil {
		fmt.Printf("verdict: %s\nreason: %s\n", c.Verdict.Verdict, c.Verdict.Reason)
	}
	if len(c.Workflow.Timings) > 0 {
		var parts []string
		var total float64
		for _, k := range sortedKeys(c.Workflow.Timings) {
			total += c.Workflow.Timings[k]
			parts = append(parts, fmt.Sprintf("%s=%.1fs", k, c.Workflow.Timings[k]))
		}
		fmt.Printf("timings: %s | total=%.1fs llm_calls=%d\n",
			strings.Join(parts, " "), total, c.Workflow.Usage.LLMCalls)
	}
	fmt.Printf("report: %s\n", filepath.Join(caseDir, string(c.ID), "report.md"))
}

// loadLLMEnv loads the LLM dotenv file: explicit --llm-env wins, else it
// probes .env in the working directory and the analyzed repo.
// Missing files are ignored; malformed lines are skipped. Guarded by
// llmEnvOnce: concurrent os.Setenv from parallel scan workers would race.
var llmEnvOnce sync.Once

func loadLLMEnv(explicit, repo string) {
	llmEnvOnce.Do(func() { loadLLMEnvOnce(explicit, repo) })
}

func loadLLMEnvOnce(explicit, repo string) {
	candidates := []string{explicit}
	if explicit == "" {
		candidates = []string{".env", filepath.Join(repo, ".env")}
	}
	for _, p := range candidates {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = llm.LoadDotEnv(p)
		return
	}
}

func sanitizeID(id string) string {
	return strings.NewReplacer("/", "-", "\\", "-", " ", "-").Replace(id)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// resolveToolchain picks the analysis toolchain for this run. The release
// binary's embedded build info wins (it is the ground truth of what
// compiled the artifact), then --release-go-version; empty means local.
func resolveToolchain(ctx context.Context, o analyzeOpts) (toolchain.Toolchain, []string) {
	want := ""
	if o.binary != "" {
		if v, err := repository.BinaryGoVersion(ctx, o.binary); err == nil {
			want = v
		}
	}
	if want == "" {
		want = o.releaseGo
	}
	return toolchain.Resolve(ctx, want)
}

// parseRootCauses accepts "pkg/path.Symbol" entries; the last dot separates
// the symbol from its package path.
func parseRootCauses(flags []string) []domain.RootCause {
	var out []domain.RootCause
	for _, f := range flags {
		for _, item := range strings.Split(f, ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			i := strings.LastIndex(item, ".")
			if i <= 0 {
				continue
			}
			out = append(out, domain.RootCause{
				Package:   item[:i],
				Symbol:    item[i+1:],
				Role:      domain.RootCauseSink,
				Mechanism: "provided manually via --root-cause",
			})
		}
	}
	return out
}

// runScan enumerates the module graph, queries OSV for every dependency
// module, and deep-analyzes each discovered advisory.
func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	maxVulns := fs.Int("max-vulns", 50, "cap on advisories to deep-analyze")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if o.repo == "" {
		usage()
	}
	absRepo, err := filepath.Abs(o.repo)
	if err != nil {
		return err
	}
	ctx := context.Background()

	// Resolve the target toolchain once — shared tools run under it.
	o.toolchain, o.tcLims = resolveToolchain(ctx, o)

	// Shared per-scan resources: one source index, one go list, one
	// govulncheck run — repeated per-advisory otherwise.
	o.goTool = affected.CachingTool(affected.ExecGoTool{Bin: o.toolchain.GoBin, Env: o.toolchain.Env})
	o.gvRunner = goanalysis.CachingRunner(goanalysis.ExecRunner{Env: o.toolchain.Env})
	o.srcIndex = &goanalysis.Index{
		Dir: absRepo,
		Env: o.toolchain.Env,
		Build: domain.ProductSnapshot{
			GOOS: o.goos, GOARCH: o.goarch, BuildTags: splitCSV(o.tags),
		},
	}

	mods, err := listModules(ctx, absRepo)
	if err != nil {
		return fmt.Errorf("list modules: %w", err)
	}
	fmt.Printf("modules: %d\n", len(mods)-1)

	var vulnIDs []string
	for _, m := range mods {
		ids, err := vulnerability.QueryOSV(ctx, o.osvURL, m)
		if err != nil {
			fmt.Fprintf(os.Stderr, "osv query %s: %v\n", m, err)
			continue
		}
		vulnIDs = dedupeAppend(vulnIDs, ids)
	}
	if len(vulnIDs) > *maxVulns {
		vulnIDs = vulnIDs[:*maxVulns]
	}
	fmt.Printf("advisories found: %d\n", len(vulnIDs))

	// Cheap deterministic pre-filter: resolve affectedness without the
	// full engine. Deterministically-not-affected advisories are recorded
	// and skipped; survivors get the full pipeline.
	snap, err := repository.Service{}.Snapshot(ctx, absRepo, repository.SnapshotOptions{
		GOOS: o.goos, GOARCH: o.goarch, BuildTags: splitCSV(o.tags),
		BinaryPath: o.binary, ReleaseGoVersion: o.releaseGo,
	})
	if err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	resolver := affected.GoResolver{Tool: o.goTool}
	src := vulnerability.OSVSource{BaseURL: o.osvURL}

	type row struct {
		ID      string `json:"id"`
		State   string `json:"state"`
		Verdict string `json:"verdict,omitempty"`
		Reason  string `json:"reason,omitempty"`
	}
	var rows []row
	var survivors []string
	for _, id := range vulnIDs {
		v, err := src.Get(ctx, id)
		if err != nil {
			rows = append(rows, row{ID: id, State: "ERROR", Reason: "advisory fetch: " + err.Error()})
			continue
		}
		res, _, err := resolver.Resolve(ctx, *v, snap)
		if err == nil && deterministicallyNotAffected(res) {
			rows = append(rows, row{ID: id, State: "FILTERED", Verdict: "NOT_AFFECTED",
				Reason: notAffectedReason(res)})
			fmt.Printf("%-18s NOT_AFFECTED (prefilter)\n", id)
			continue
		}
		survivors = append(survivors, id)
	}

	// Deep-analyze survivors in parallel: the shared index/tool/runner are
	// mutex/once-guarded, and each case keeps its own evidence and budget.
	loadLLMEnv(o.llmEnv, absRepo) // resolved once, before workers read env
	const workers = 4
	sem := make(chan struct{}, workers)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, id := range survivors {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			co := o
			co.vulnID = id
			c, err := analyzeCase(ctx, co)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", id, err)
				rows = append(rows, row{ID: id, State: "ERROR", Reason: err.Error()})
				return
			}
			r := row{ID: id, State: string(c.Workflow.State)}
			if c.Verdict != nil {
				r.Verdict = string(c.Verdict.Verdict)
				r.Reason = c.Verdict.Reason
			}
			rows = append(rows, r)
			var tm string
			var total float64
			for _, sec := range c.Workflow.Timings {
				total += sec
			}
			if total > 0 {
				tm = fmt.Sprintf(" (%.0fs, %d llm calls)", total, c.Workflow.Usage.LLMCalls)
			}
			fmt.Printf("%-18s %s %s%s\n", id, r.Verdict, r.Reason, tm)
		}(id)
	}
	wg.Wait()
	b, _ := json.MarshalIndent(rows, "", "  ")
	out := filepath.Join(o.caseDir, "scan.json")
	if err := os.MkdirAll(o.caseDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(out, b, 0o644); err != nil {
		return err
	}
	fmt.Printf("scan report: %s\n", out)
	return nil
}

// listModules returns the module paths in the repository's module graph,
// excluding the main module itself.
func listModules(ctx context.Context, repo string) ([]string, error) {
	cmd := exec.CommandContext(ctx, "go", "list", "-m", "all")
	cmd.Dir = repo
	out, err := cmd.Output()
	if err != nil {
		// Vendor mode: `go list -m all` refuses; modules.txt is authoritative.
		if vm := vendorModulePaths(repo); vm != nil {
			return vm, nil
		}
		return nil, err
	}
	var mods []string
	for i, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if i == 0 {
			continue // main module
		}
		if f := strings.Fields(line); len(f) > 0 {
			mods = append(mods, f[0])
		}
	}
	return mods, nil
}

// vendorModulePaths reads module paths from vendor/modules.txt when the
// repository vendors its dependencies.
func vendorModulePaths(repo string) []string {
	b, err := os.ReadFile(filepath.Join(repo, "vendor", "modules.txt"))
	if err != nil {
		return nil
	}
	var mods []string
	for _, m := range affected.ParseVendorModules(b) {
		mods = append(mods, m.Path)
	}
	return mods
}

// dedupeAppend adds ids not already present, preserving order.
func dedupeAppend(dst, ids []string) []string {
	seen := map[string]bool{}
	for _, id := range dst {
		seen[id] = true
	}
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			dst = append(dst, id)
		}
	}
	return dst
}

// deterministicallyNotAffected mirrors the verdict rule: any single
// deterministic FALSE on the affected chain means the component cannot
// be present at all.
func deterministicallyNotAffected(r domain.AffectedResult) bool {
	return r.ModulePresent == domain.ClaimFalse ||
		r.VersionAffected == domain.ClaimFalse ||
		r.PackagePresent == domain.ClaimFalse ||
		r.BuildRelevant == domain.ClaimFalse
}

func notAffectedReason(r domain.AffectedResult) string {
	switch {
	case r.ModulePresent == domain.ClaimFalse:
		return "vulnerable module is not part of the product dependency graph"
	case r.VersionAffected == domain.ClaimFalse:
		return "resolved dependency version is outside affected range"
	case r.PackagePresent == domain.ClaimFalse:
		return "affected package is not imported by the product build"
	case r.BuildRelevant == domain.ClaimFalse:
		return "affected package excluded by GOOS/GOARCH/build tags"
	}
	return ""
}

func sortedKeys(m map[string]float64) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
