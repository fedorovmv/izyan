package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/eval"
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/toolchain"
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
	}
	repo := o.repo
	if repo == "" {
		repo = corpus.Repo
	}
	if repo == "" {
		for _, c := range corpus.Cases {
			if c.Repo == "" {
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

	ctx := context.Background()
	var rep eval.Report
	for _, c := range corpus.Cases {
		co := o
		co.vulnID = c.Vuln
		co.vulnFile = c.VulnFile
		co.exploitModel = c.ExploitModel
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
		if c.Repo != "" {
			absCase, err := filepath.Abs(c.Repo)
			if err != nil {
				rep.Record(c, "", "", nil, err)
				continue
			}
			co.repo = absCase
			// A case on a different repo cannot share the corpus index.
			if absCase != o.repo {
				co.srcIndex = nil
			}
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
		res := rep.Results[len(rep.Results)-1]
		mark := "  "
		if res.FalseSafe {
			mark = "!!"
		} else if res.ExpectOK != nil && !*res.ExpectOK {
			mark = "!!"
		} else if res.Err != "" {
			mark = "??"
		}
		fmt.Printf("%s %-28s %-22s %s\n", mark, c.Label(), firstNonEmpty(res.Verdict, res.Err), res.Reason)
	}

	m := rep.Metrics
	fmt.Printf("\ncases=%d errors=%d expect pass=%d fail=%d claims-fail=%d false-safe=%d inconclusive=%d\n",
		m.Total, m.Errors, m.ExpectPass, m.ExpectFail, m.ClaimsFail, m.FalseSafe, m.Inconclusive)
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
