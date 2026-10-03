package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/eval"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/toolchain"
	"github.com/fedorovmv/izyan/internal/vulnerability"
)

// runEval executes a corpus of cases through the full pipeline and
// reports the spec's quality metrics — the false-safe count above all.
//
//	izyan eval --corpus eval/corpus.json [--repo <path>]
//	    [--case <id|glob>] [-j <jobs>] [--clean]
//	    [--out report.md] [--json report.json] [common flags]
//
// Exit code is 1 when any case is false-safe or fails its expectation;
// informational cases never fail the run.
func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	corpusPath := fs.String("corpus", "", "evaluation corpus JSON")
	caseFilter := fs.String("case", "", "comma-separated list or pattern of case IDs to run (e.g. 'real-yaml*', 'real-yaml-const')")
	jobs := fs.Int("j", 4, "number of parallel case evaluations (default 4; 1 for sequential)")
	clean := fs.Bool("clean", false, "force re-materialization of generated product modules (wipe .gen)")
	outMD := fs.String("out", "", "write markdown report to file")
	outJSON := fs.String("json", "", "write JSON report to file")
	// Regression runs must be reproducible: LLM proposals are
	// nondeterministic, so the corpus is deterministic-only by default.
	withLLM := fs.Bool("with-llm", false, "enable LLM proposals (nondeterministic)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *corpusPath == "" {
		usage()
	}
	kb, err := loadKnowledgeBase(o.knowledge)
	if err != nil {
		return err
	}
	o.kb = kb
	// Case state defaults to a temp dir for eval runs — persisted cases stay
	// available via --case-dir for debugging a failure.
	caseDirSet := false
	fs.Visit(func(f *flag.Flag) { caseDirSet = caseDirSet || f.Name == "case-dir" })
	raw, err := os.ReadFile(*corpusPath)
	if err != nil {
		return fmt.Errorf("corpus: %w", err)
	}
	var corpus eval.Corpus
	if err := json.Unmarshal(raw, &corpus); err != nil {
		return fmt.Errorf("corpus: %w", err)
	}
	if len(corpus.Cases) == 0 {
		return fmt.Errorf("corpus: no cases")
	}
	// Relative paths in the corpus resolve against the corpus file's
	// directory, not the caller's cwd.
	absCorpus, err := filepath.Abs(*corpusPath)
	if err != nil {
		return err
	}
	base := filepath.Dir(absCorpus)
	resolve := func(p string) string {
		p = os.ExpandEnv(p)
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	corpus.Repo = resolve(corpus.Repo)
	for i := range corpus.Cases {
		corpus.Cases[i].Repo = resolve(corpus.Cases[i].Repo)
		corpus.Cases[i].VulnFile = resolve(corpus.Cases[i].VulnFile)
		corpus.Cases[i].ExploitModel = resolve(corpus.Cases[i].ExploitModel)
		corpus.Cases[i].Product = resolve(corpus.Cases[i].Product)
	}

	if *caseFilter != "" {
		patterns := strings.Split(*caseFilter, ",")
		for i := range patterns {
			patterns[i] = strings.TrimSpace(patterns[i])
		}
		var filtered []eval.Case
		for _, c := range corpus.Cases {
			lbl := c.Label()
			matched := false
			for _, pat := range patterns {
				if pat == "" {
					continue
				}
				if pat == lbl {
					matched = true
					break
				}
				if m, _ := filepath.Match(pat, lbl); m {
					matched = true
					break
				}
			}
			if matched {
				filtered = append(filtered, c)
			}
		}
		if len(filtered) == 0 {
			return fmt.Errorf("no cases matching --case %q", *caseFilter)
		}
		corpus.Cases = filtered
	}

	repo := o.repo
	if repo == "" {
		repo = corpus.Repo
	}
	if repo == "" {
		for _, c := range corpus.Cases {
			if c.Repo == "" && c.Product == "" {
				return fmt.Errorf("no repository: set --repo, corpus.repo, or per-case repo")
			}
		}
	}

	// Corpus-level toolchain: case go_version is a per-case override;
	// the shared toolchain serves cases without one.
	o.toolchain, o.tcLims = resolveToolchain(context.Background(), o)

	o.goTool = affected.CachingTool(affected.ExecGoTool{Bin: o.toolchain.GoBin, Env: o.toolchain.Env})
	o.gvRunner = goanalysis.CachingRunner(goanalysis.ExecRunner{Env: o.toolchain.Env})
	var absRepo string
	if repo != "" {
		// A shared repo lets cases reuse one source index, like scan mode.
		absRepo, err = filepath.Abs(repo)
		if err != nil {
			return err
		}
		o.repo = absRepo
		o.srcIndex = &goanalysis.Index{
			Dir: absRepo,
			Env: o.toolchain.Env,
			KB:  o.kb,
			Build: domain.ProductSnapshot{
				GOOS: o.goos, GOARCH: o.goarch, BuildTags: splitCSV(o.tags),
			},
		}
	}
	if *withLLM {
		loadLLMEnv(o.llmEnv, absRepo)
	} else {
		o.detOnly = true
	}
	if !caseDirSet {
		o.caseDir = filepath.Join(os.TempDir(), fmt.Sprintf("izyan-eval-%d", os.Getpid()))
	}
	fmt.Fprintf(os.Stderr, "corpus=%s cases=%d repo=%s case-dir=%s\n",
		*corpusPath, len(corpus.Cases), absRepo, o.caseDir)

	budget, err := parseMemLimit(o.memLimit)
	if err != nil {
		return err
	}
	ctx, stop := applyMemoryLimit(context.Background(), budget)
	defer stop()
	gen := eval.Gen{GoBin: o.toolchain.GoBin, Env: o.toolchain.Env, Force: *clean}
	genRoot := filepath.Join(base, ".gen")

	total := len(corpus.Cases)
	outcomes := make([]caseOutcome, total)

	concurrency := *jobs
	if concurrency < 1 {
		concurrency = 1
	}
	if concurrency > total {
		concurrency = total
	}

	tasks := make(chan int, total)
	results := make(chan caseOutcome, total)

	for i := 0; i < total; i++ {
		tasks <- i
	}
	close(tasks)

	var wg sync.WaitGroup
	for w := 0; w < concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range tasks {
				c := corpus.Cases[idx]
				outcomes := runCase(ctx, idx, total, c, o, base, genRoot, gen)
				results <- outcomes
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	var rep eval.Report
	completed := 0
	for outcome := range results {
		completed++
		outcomes[outcome.idx] = outcome

		mark := "  "
		if outcome.err != nil {
			mark = "??"
		} else {
			ok := false
			for _, want := range outcome.c.Expect {
				if string(outcome.verdict) == want {
					ok = true
					break
				}
			}
			if len(outcome.c.Expect) > 0 && !ok {
				mark = "!!"
			}
		}
		errStr := ""
		if outcome.err != nil {
			errStr = outcome.err.Error()
		}
		fmt.Printf("%s [%d/%d] %-28s %-22s %s (%.0fs)\n", mark, completed, total, outcome.c.Label(),
			firstNonEmpty(string(outcome.verdict), errStr), outcome.reason, outcome.duration.Seconds())
		if outcome.topTimingsStr != "" {
			fmt.Fprintf(os.Stderr, "  states: %s\n", outcome.topTimingsStr)
		}
	}

	// Record in original corpus order
	for _, outcome := range outcomes {
		rep.Record(outcome.c, outcome.verdict, outcome.reason, outcome.claims, outcome.err)
		if outcome.baseline != "" {
			rep.RecordBaseline(outcome.baseline)
		}
	}

	m := rep.Metrics
	fmt.Printf("\ncases=%d errors=%d expect pass=%d fail=%d claims-fail=%d false-safe=%d inconclusive=%d\n",
		m.Total, m.Errors, m.ExpectPass, m.ExpectFail, m.ClaimsFail, m.FalseSafe, m.Inconclusive)
	if m.GovulncheckSignals > 0 {
		fmt.Printf("signal-cleared=%d/%d\n", m.SignalCleared, m.GovulncheckSignals)
		fmt.Printf("reachable-cleared=%d/%d package-level-cleared=%d/%d\n",
			m.ReachableCleared, m.ReachableSignals, m.PackageLevelCleared, m.PackageLevelSignals)
	}
	if *outMD != "" {
		if err := os.WriteFile(*outMD, []byte(rep.Markdown()), 0o644); err != nil {
			return err
		}
	}
	if *outJSON != "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(*outJSON, append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	if m.FalseSafe > 0 || m.ExpectFail > 0 || m.ClaimsFail > 0 || m.Errors > 0 {
		return fmt.Errorf("evaluation failed: false-safe=%d expect-fail=%d claims-fail=%d errors=%d",
			m.FalseSafe, m.ExpectFail, m.ClaimsFail, m.Errors)
	}
	return nil
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// topTimings renders the n workflow states that consumed the most case
// time — the eval progress diagnostic answering "where is it spending
// the minutes" without digging through the persisted case.
func topTimings(timings map[string]float64, n int) string {
	type kv struct {
		k string
		v float64
	}
	var sorted []kv
	for k, v := range timings {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	if len(sorted) > n {
		sorted = sorted[:n]
	}
	parts := make([]string, 0, len(sorted))
	for _, s := range sorted {
		parts = append(parts, fmt.Sprintf("%s=%.0fs", s.k, s.v))
	}
	return strings.Join(parts, " ")
}

// baselineVuln resolves the advisory identity for the standalone
// govulncheck baseline: the pipeline's parsed document when available,
// else the case's vuln file, else the bare id.
func baselineVuln(ctx context.Context, c eval.Case, cs *domain.AnalysisCase) domain.Vulnerability {
	if cs != nil && cs.Vulnerability.ID != "" {
		return cs.Vulnerability
	}
	if c.VulnFile != "" {
		if v, err := (vulnerability.FileSource{Path: c.VulnFile}).Get(ctx, c.Vuln); err == nil && v != nil {
			return *v
		}
	}
	return domain.Vulnerability{ID: c.Vuln}
}

type caseOutcome struct {
	idx           int
	c             eval.Case
	verdict       domain.Verdict
	reason        string
	claims        map[string]string
	err           error
	baseline      string
	duration      time.Duration
	topTimingsStr string
}

func runCase(ctx context.Context, idx, total int, c eval.Case, o analyzeOpts, base, genRoot string, gen eval.Gen) caseOutcome {
	caseStart := time.Now()
	co := o
	co.vulnID = c.Vuln
	co.vulnFile = c.VulnFile
	co.exploitModel = c.ExploitModel
	platformOverride := false
	if c.GOOS != "" {
		co.goos = c.GOOS
		platformOverride = true
	}
	if c.GOARCH != "" {
		co.goarch = c.GOARCH
		platformOverride = true
	}
	if len(c.BuildTags) > 0 {
		co.tags = strings.Join(c.BuildTags, ",")
		platformOverride = true
	}
	if c.GoVersion != "" {
		co.releaseGo = c.GoVersion
		co.toolchain = toolchain.Toolchain{}
		co.srcIndex = nil
		co.goTool = nil
		co.gvRunner = nil
	}
	co.manualRC = nil
	for _, rc := range c.RootCauses {
		co.manualRC = append(co.manualRC, rc.RootCause)
	}
	co.nonLocusBasis = c.NonLocus
	var productDir string
	switch {
	case c.Product != "" && c.Repo != "":
		return caseOutcome{idx: idx, c: c, err: fmt.Errorf("case sets both repo and product — they are mutually exclusive"), duration: time.Since(caseStart)}
	case c.Product == "" && (c.Module != "" || len(c.Deps) > 0):
		return caseOutcome{idx: idx, c: c, err: fmt.Errorf("module/deps declared without a product"), duration: time.Since(caseStart)}
	case c.Product != "":
		dir, err := gen.Materialize(ctx, c, base, genRoot)
		if err != nil {
			return caseOutcome{idx: idx, c: c, err: err, duration: time.Since(caseStart)}
		}
		productDir = dir
		co.repo = dir
	}
	if c.Repo != "" {
		absCase, err := filepath.Abs(c.Repo)
		if err != nil {
			return caseOutcome{idx: idx, c: c, err: err, duration: time.Since(caseStart)}
		}
		co.repo = absCase
	}
	if co.repo != o.repo || platformOverride {
		co.srcIndex = nil
		co.goTool = nil
		co.gvRunner = nil
	}
	if o.caseDir != "" {
		co.caseDir = filepath.Join(o.caseDir, sanitizeCaseName(c.Label()))
	}
	cs, err := analyzeCase(ctx, co)
	var verdict domain.Verdict
	var reason string
	claims := map[string]string{}
	var topTimingsStr string
	if cs != nil {
		if cs.Verdict != nil {
			verdict = cs.Verdict.Verdict
			reason = cs.Verdict.Reason
		}
		for _, cl := range cs.Claims {
			claims[string(cl.ConditionID)] = string(cl.Result)
		}
		topTimingsStr = topTimings(cs.Workflow.Timings, 3)
	}

	var baseline string
	if productDir != "" {
		var gvRaw []byte
		if cs != nil {
			for _, ev := range cs.EvidenceGraph.Evidence {
				if ev.Kind == domain.EvidenceGovulncheck && ev.Content != "" {
					gvRaw = []byte(ev.Content)
					break
				}
			}
		}
		if len(gvRaw) > 0 {
			baseline = eval.BaselineFromOutput(gvRaw, baselineVuln(ctx, c, cs))
		} else {
			baseline = eval.Baseline(ctx,
				goanalysis.ExecRunner{Env: co.toolchain.Env}, productDir,
				baselineVuln(ctx, c, cs), domain.ProductSnapshot{
					GOOS: co.goos, GOARCH: co.goarch, BuildTags: splitCSV(co.tags),
				})
		}
	}

	return caseOutcome{
		idx:           idx,
		c:             c,
		verdict:       verdict,
		reason:        reason,
		claims:        claims,
		err:           err,
		baseline:      baseline,
		duration:      time.Since(caseStart),
		topTimingsStr: topTimingsStr,
	}
}

func sanitizeCaseName(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '_'
	}, s)
}
