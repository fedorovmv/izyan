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
	"time"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/eval"
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/toolchain"
	"example.com/vuln-analyzer/internal/vulnerability"
)

// runEval executes a corpus of cases through the full pipeline and
// reports the spec's quality metrics — the false-safe count above all.
//
//	vuln-analyzer eval --corpus eval/corpus.json [--repo <path>]
//	    [--out report.md] [--json report.json] [common flags]
//
// Exit code is 1 when any case is false-safe or fails its expectation;
// informational cases never fail the run.
func runEval(args []string) error {
	fs := flag.NewFlagSet("eval", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	corpusPath := fs.String("corpus", "", "evaluation corpus JSON")
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
		o.caseDir = filepath.Join(os.TempDir(), fmt.Sprintf("vuln-eval-%d", os.Getpid()))
	}
	fmt.Fprintf(os.Stderr, "corpus=%s cases=%d repo=%s case-dir=%s\n",
		*corpusPath, len(corpus.Cases), absRepo, o.caseDir)

	budget, err := parseMemLimit(o.memLimit)
	if err != nil {
		return err
	}
	ctx, stop := applyMemoryLimit(context.Background(), budget)
	defer stop()
	gen := eval.Gen{GoBin: o.toolchain.GoBin, Env: o.toolchain.Env}
	genRoot := filepath.Join(base, ".gen")
	var rep eval.Report
	for i, c := range corpus.Cases {
		fmt.Fprintf(os.Stderr, "→ case %d/%d %s\n", i+1, len(corpus.Cases), c.Label())
		caseStart := time.Now()
		co := o
		co.vulnID = c.Vuln
		co.vulnFile = c.VulnFile
		co.exploitModel = c.ExploitModel
		// Platform overrides change the build shape — package selection,
		// dep graph and source index all differ per GOOS/GOARCH/tags, so
		// corpus-level caches computed under the default platform are
		// invalid for this case even when the repo is unchanged.
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
			// Per-case toolchain: shared tools/index carry the corpus-level
			// env — rebuild under this case's toolchain instead.
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
		var productDir string
		switch {
		case c.Product != "" && c.Repo != "":
			rep.Record(c, "", "", nil, fmt.Errorf("case sets both repo and product — they are mutually exclusive"))
			continue
		case c.Product == "" && (c.Module != "" || len(c.Deps) > 0):
			rep.Record(c, "", "", nil, fmt.Errorf("module/deps declared without a product"))
			continue
		case c.Product != "":
			// Generated-manifest product: sources are committed, the
			// vulnerable manifest is generated under .gen/.
			dir, err := gen.Materialize(ctx, c, base, genRoot)
			if err != nil {
				rep.Record(c, "", "", nil, err)
				continue
			}
			productDir = dir
			co.repo = dir
		}
		if c.Repo != "" {
			absCase, err := filepath.Abs(c.Repo)
			if err != nil {
				rep.Record(c, "", "", nil, err)
				continue
			}
			co.repo = absCase
		}
		if co.repo != o.repo || platformOverride {
			// Per-repo/per-platform tools cannot share corpus-level
			// caches: a cached `go list`/govulncheck output names the
			// first configuration's module graph and package selection,
			// which is wrong for any other product or target platform.
			co.srcIndex = nil
			co.goTool = nil
			co.gvRunner = nil
		}
		cs, err := analyzeCase(ctx, co)
		var verdict domain.Verdict
		var reason string
		claims := map[string]string{}
		if cs != nil {
			if cs.Verdict != nil {
				verdict = cs.Verdict.Verdict
				reason = cs.Verdict.Reason
			}
			for _, cl := range cs.Claims {
				claims[string(cl.ConditionID)] = string(cl.Result)
			}
		}
		rep.Record(c, verdict, reason, claims, err)
		if productDir != "" {
			// Baseline: what standalone govulncheck says about this
			// advisory on this product — differentiation evidence.
			rep.RecordBaseline(eval.Baseline(ctx,
				goanalysis.ExecRunner{Env: co.toolchain.Env}, productDir,
				baselineVuln(ctx, c, cs), domain.ProductSnapshot{
					GOOS: co.goos, GOARCH: co.goarch, BuildTags: splitCSV(co.tags),
				}))
		}
		res := rep.Results[len(rep.Results)-1]
		mark := "  "
		if res.FalseSafe {
			mark = "!!"
		} else if res.ExpectOK != nil && !*res.ExpectOK {
			mark = "!!"
		} else if res.Err != "" {
			mark = "??"
		}
		fmt.Printf("%s %-28s %-22s %s (%.0fs)\n", mark, c.Label(),
			firstNonEmpty(res.Verdict, res.Err), res.Reason, time.Since(caseStart).Seconds())
		if cs != nil {
			fmt.Fprintf(os.Stderr, "  states: %s\n", topTimings(cs.Workflow.Timings, 3))
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
