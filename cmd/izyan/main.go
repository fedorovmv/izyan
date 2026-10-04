package main

import (
	"bytes"
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

	"github.com/fedorovmv/izyan/internal/affected"
	"github.com/fedorovmv/izyan/internal/domain"
	"github.com/fedorovmv/izyan/internal/evaluator"
	"github.com/fedorovmv/izyan/internal/exploit"
	"github.com/fedorovmv/izyan/internal/fix"
	"github.com/fedorovmv/izyan/internal/goanalysis"
	"github.com/fedorovmv/izyan/internal/llm"
	"github.com/fedorovmv/izyan/internal/persistence/filesystem"
	"github.com/fedorovmv/izyan/internal/report"
	"github.com/fedorovmv/izyan/internal/repository"
	"github.com/fedorovmv/izyan/internal/review"
	"github.com/fedorovmv/izyan/internal/rootcause"
	"github.com/fedorovmv/izyan/internal/states"
	"github.com/fedorovmv/izyan/internal/toolaudit"
	"github.com/fedorovmv/izyan/internal/toolchain"
	"github.com/fedorovmv/izyan/internal/tracker"
	"github.com/fedorovmv/izyan/internal/vulnerability"
	"github.com/fedorovmv/izyan/internal/workflow"
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
	case "knowledge":
		err = runKnowledge(os.Args[2:])
	case "version", "-version", "--version", "-v":
		printVersion()
		return
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
  izyan analyze --repo <path> --vuln <GO-/CVE-/GHSA-id> [options]
  izyan scan    --repo <path> [options]   # all advisories for all modules
  izyan eval    --corpus <path> [--repo <path>] [--case <id|glob>] [-j <n>] [--clean] [options]  # corpus regression run
  izyan remediate --repo <path> --vuln <id> [--apply] [--run-tests]  # plan/apply fix + re-analyze
  izyan knowledge [--knowledge <path>]  # dump the effective ecosystem knowledge base
  izyan version                           # show version information

options:
  --vuln-file <path>     load advisory from local OSV JSON instead of api.osv.dev
  --ticket <path>        tracker ticket JSON, arbitrary text, or '-' for stdin
  --ticket-id <id>       ticket key to select when input contains multiple tickets
  --repo-map <path>      path to JSON mapping component/ticket keys to repo paths
  --osv-url <url>        override OSV API base URL
  --case-dir <dir>       analysis state directory (default .izyan)
  --case <id|glob>       filter cases to run in eval (comma-separated or glob)
  -j <n>                 parallel worker pool concurrency for eval (default: 4)
  --clean                force re-materialization of generated modules in eval
  --goos/--goarch        target platform (default: host)
  --build-tags a,b       build tags
  --root-cause p.Sym     manual root cause symbol (repeatable, comma-separated)
  --exploit-model <path> manual exploit model JSON
  --knowledge <path>     extend the ecosystem knowledge base (JSON, additive)
  --non-locus-basis <path> JSON file with expert non-locus basis decisions
  --accept-locus-proposals adopt machine-generated non_locus recommendations into expert basis
  --cve-analysis <off|assist|verified>  LLM CVE analysis profile (default: off)
  --llm-intake           use LLM to extract vulnerability and metadata from unstructured ticket text
  --checkout-release     resolve release/tag and analyze in an isolated git worktree
  --release <tag|ref>    explicit release tag or git ref to analyze (or --git-ref)
  --lang <ru|en>         report and output language (default: ru)
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
	ticketID      string
	ticketComp    string
	ticketRel     string
	ticketKey     string
	llmIntake     bool
	checkoutRel   bool
	releaseRef    string
	worktreeRef   string
	worktreeSHA   string
	repoMap       string
	cveAnalysis   string
	lang          string
	exploitModel  string
	llmEnv        string
	knowledge     string
	detOnly       bool
	allowExec     bool
	strictLLM     bool
	memLimit      string
	rootCauseArgs []string
	// manualRC carries already-parsed root causes (eval corpus entries
	// support the object form, which rootCauseArgs strings cannot express).
	manualRC []domain.RootCause
	// nonLocusBasis carries expert necessity decisions — declared symbols
	// asserted not to be defect loci — into the case. Loaded from the
	// -non-locus-basis JSON file or from an eval corpus entry.
	nonLocusBasis []domain.LocusDecision
	nonLocusFile  string
	// acceptLocusProposals adopts machine-generated non_locus proposals as basis.
	acceptLocusProposals bool
	trustedPeer          bool
	// toolchain is the resolved target Go toolchain; zero value = local.
	toolchain toolchain.Toolchain
	// tcLims carries resolution notes into the case's limitations.
	tcLims []string
	// Shared across advisories in scan mode; nil in single analyze.
	srcIndex *goanalysis.Index
	goTool   affected.GoTool
	gvRunner goanalysis.Runner
	// kb is the resolved ecosystem knowledge base (default + --knowledge
	// extension); nil = built-in defaults.
	kb *goanalysis.Knowledge
}

// commonFlags registers the flags shared by analyze and scan.
func commonFlags(fs *flag.FlagSet, o *analyzeOpts) {
	fs.StringVar(&o.repo, "repo", "", "path to Go repository")
	fs.StringVar(&o.osvURL, "osv-url", "", "OSV API base URL")
	fs.StringVar(&o.caseDir, "case-dir", ".izyan", "case state directory")
	fs.StringVar(&o.goos, "goos", "", "target GOOS")
	fs.StringVar(&o.goarch, "goarch", "", "target GOARCH")
	fs.StringVar(&o.tags, "build-tags", "", "comma-separated build tags")
	fs.StringVar(&o.binary, "binary", "", "release-built Go binary: govulncheck -mode binary + embedded toolchain")
	fs.StringVar(&o.releaseGo, "release-go-version", "", "toolchain version that built the release (e.g. from the ticket)")
	fs.StringVar(&o.cveAnalysis, "cve-analysis", "off", "LLM CVE analysis profile: off, assist, verified")
	fs.BoolVar(&o.detOnly, "deterministic-only", false, "disable LLM-backed states")
	fs.BoolVar(&o.allowExec, "allow-exec", false, "permit executing repository code for build/test evidence (run_build/run_tests)")
	fs.BoolVar(&o.strictLLM, "strict-llm", false, "fail fast on LLM errors/refusals without fallback to deterministic code")
	fs.StringVar(&o.llmEnv, "llm-env", "", "path to LLM .env file (default: .env in cwd or repo)")
	fs.StringVar(&o.knowledge, "knowledge", "", "extend the ecosystem knowledge base with a JSON file (see internal/goanalysis/knowledge.go)")
	fs.StringVar(&o.memLimit, "mem-limit", "4GiB", "analyzer memory ceiling (e.g. 4GiB, 512MiB; 0 disables) — real products can pull very large dependency graphs into the index")
	fs.StringVar(&o.nonLocusFile, "non-locus-basis", "", "JSON file with expert non-locus decisions: [{\"symbol\":{\"package\":\"pkg\",\"symbol\":\"Type.Name\"},\"basis\":\"why it is not a defect site\",\"authority\":\"review ref\"}]")
	fs.BoolVar(&o.acceptLocusProposals, "accept-locus-proposals", false, "adopt machine-generated non_locus recommendations into expert basis")
	fs.BoolVar(&o.trustedPeer, "trusted-peer", false, "declare deployment in trusted infrastructure / communication with trusted peers only (falsifies untrusted peer/network input)")
	fs.BoolVar(&o.checkoutRel, "checkout-release", false, "resolve release/tag from ticket or --release and run analysis in an isolated git worktree")
	fs.StringVar(&o.releaseRef, "release", "", "explicit release tag, branch, or commit to analyze (overrides ticket release)")
	fs.StringVar(&o.releaseRef, "git-ref", "", "alias for --release")
	fs.StringVar(&o.lang, "lang", "ru", "report and output language: ru (default) or en")
}

// loadKnowledgeBase resolves the --knowledge extension: built-in
// defaults plus the additive entries from the JSON file. Empty path —
// nil, the index falls back to DefaultKnowledge().
func loadKnowledgeBase(path string) (*goanalysis.Knowledge, error) {
	if path == "" {
		return nil, nil
	}
	f, err := goanalysis.LoadKnowledgeFile(path)
	if err != nil {
		return nil, fmt.Errorf("knowledge: %w", err)
	}
	// Files without a declared name identify in reports by their path.
	if f.Name == "" {
		f.Name = filepath.Base(path)
	}
	kb := goanalysis.DefaultKnowledge()
	if err := kb.Merge(f); err != nil {
		return nil, fmt.Errorf("knowledge: %w", err)
	}
	return kb, nil
}

// runKnowledge prints the effective ecosystem knowledge base in the
// extension-file schema: the embedded defaults by themselves, or
// defaults merged with a --knowledge extension. Users copy the output
// as the starting point for their own extension files; the command also
// doubles as a validator — a bad extension file fails here.
func runKnowledge(args []string) error {
	fs := flag.NewFlagSet("knowledge", flag.ExitOnError)
	var o analyzeOpts
	fs.StringVar(&o.knowledge, "knowledge", "", "extension JSON merged over the embedded defaults")
	if err := fs.Parse(args); err != nil {
		return err
	}
	kb, err := loadKnowledgeBase(o.knowledge)
	if err != nil {
		return err
	}
	if kb == nil {
		kb = goanalysis.DefaultKnowledge()
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(kb.AsFile())
}

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	fs.StringVar(&o.vulnID, "vuln", "", "vulnerability id (GO-/CVE-/GHSA-)")
	fs.StringVar(&o.vulnFile, "vuln-file", "", "local OSV JSON file")
	fs.StringVar(&o.exploitModel, "exploit-model", "", "manual exploit model JSON")
	ticketPath := fs.String("ticket", "", "tracker ticket JSON, arbitrary text, or '-' for stdin")
	ticketKey := fs.String("ticket-id", "", "ticket key/id to select if ticket input contains multiple tickets")
	repoMapPath := fs.String("repo-map", "", "path to JSON mapping component/ticket keys to local repo paths")
	llmIntake := fs.Bool("llm-intake", false, "use LLM to extract vulnerability and metadata from unstructured ticket text")
	var rootCauseFlags stringList
	fs.Var(&rootCauseFlags, "root-cause", "manual root cause as pkg/path.Symbol (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.rootCauseArgs = rootCauseFlags
	if *ticketKey != "" {
		o.ticketKey = *ticketKey
	}
	if *repoMapPath != "" {
		o.repoMap = *repoMapPath
	}
	o.llmIntake = *llmIntake
	if *ticketPath != "" {
		loadLLMEnv(o.llmEnv, o.repo)
		llmCfg := llm.ConfigFromEnv()
		var completer tracker.TextCompleter
		if o.llmIntake {
			if !llmCfg.Enabled || o.detOnly {
				return fmt.Errorf("--llm-intake: cannot use --llm-intake when LLM is disabled or --deterministic-only is set")
			}
			completer = llmCompleterAdapter{client: llm.NewClient(llmCfg), role: llm.Build}
		} else if llmCfg.Enabled && !o.detOnly {
			completer = llmCompleterAdapter{client: llm.NewClient(llmCfg), role: llm.Build}
		}
		if err := applyTicket(&o, *ticketPath, completer); err != nil {
			return err
		}
	}
	if o.vulnID == "" && o.vulnFile != "" {
		if b, err := os.ReadFile(o.vulnFile); err == nil {
			var doc struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(b, &doc); err == nil && doc.ID != "" {
				o.vulnID = doc.ID
			}
		}
	}
	if o.repo == "" || o.vulnID == "" {
		usage()
	}
	var err error
	if o.kb, err = loadKnowledgeBase(o.knowledge); err != nil {
		return err
	}
	budget, err := parseMemLimit(o.memLimit)
	if err != nil {
		return err
	}
	ctx, stop := applyMemoryLimit(context.Background(), budget)
	defer stop()
	wtCleanup, err := prepareReleaseWorktree(ctx, &o)
	if err != nil {
		return err
	}
	if wtCleanup != nil {
		defer wtCleanup()
	}
	c, err := analyzeCase(ctx, o)
	if err != nil {
		return err
	}
	printCase(c, o.caseDir, o.lang)
	if o.strictLLM && c.Workflow.State == domain.StateFailed {
		return fmt.Errorf("strict-llm: analysis failed in state %s", c.Workflow.State)
	}
	return nil
}

// applyTicket folds a generic tracker ticket or extracted ticket metadata into analyze options:
// explicit CLI flags win over ticket fields (ticket is the default, not an override).
// If repo is unset, repo-map or default repos.json resolution is attempted against component/product/ticket.
func applyTicket(o *analyzeOpts, path string, completer tracker.TextCompleter) error {
	t, err := tracker.LoadTicketWithOptions(path, o.ticketKey, completer)
	if err != nil {
		return err
	}
	if o.vulnID == "" {
		o.vulnID = t.Vulnerability
	}
	if o.ticketID == "" && t.ID != "" {
		o.ticketID = t.ID
	}
	if o.ticketComp == "" && t.Component != "" {
		o.ticketComp = t.Component
	}
	if o.ticketRel == "" && t.Release != "" {
		o.ticketRel = t.Release
	}

	// Resolve repo if not explicitly provided
	if o.repo == "" {
		var rm *tracker.RepoMap
		if o.repoMap != "" {
			var err error
			rm, err = tracker.LoadRepoMap(o.repoMap)
			if err != nil {
				return fmt.Errorf("load repo-map %s: %w", o.repoMap, err)
			}
		} else {
			// Look for default repos.json or .izyan-repos.json in current directory
			for _, candidate := range []string{"repos.json", ".izyan-repos.json"} {
				if _, err := os.Stat(candidate); err == nil {
					if loaded, err := tracker.LoadRepoMap(candidate); err == nil {
						rm = loaded
						break
					}
				}
			}
		}

		if rm != nil {
			if resolved := rm.Resolve(t); resolved != "" {
				o.repo = resolved
			}
		}
		if o.repo == "" && t.Repo != "" {
			o.repo = t.Repo
		}
	}

	if o.vulnFile == "" && (len(t.OSV) > 0 || (t.Module != "" && len(t.FixedVersions) > 0)) {
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

func prepareReleaseWorktree(ctx context.Context, o *analyzeOpts) (func(), error) {
	if o.releaseRef != "" {
		o.ticketRel = o.releaseRef
	}
	if !o.checkoutRel {
		return nil, nil
	}
	if o.ticketRel == "" {
		return nil, fmt.Errorf("--checkout-release: no release specified (provide via --release or --ticket)")
	}
	if o.repo == "" {
		return nil, fmt.Errorf("--checkout-release: repository path (--repo) is required")
	}

	resolvedRef, sha, err := repository.ResolveRef(ctx, o.repo, o.ticketRel)
	if err != nil {
		return nil, fmt.Errorf("checkout release %q: %w", o.ticketRel, err)
	}

	o.worktreeRef = resolvedRef
	o.worktreeSHA = sha

	// Check if current clean HEAD already points to the resolved commit
	_, headSHA, headErr := repository.ResolveRef(ctx, o.repo, "HEAD")
	if headErr == nil && headSHA == sha {
		dirtyOut, _ := exec.CommandContext(ctx, "git", "-C", o.repo, "status", "--porcelain").Output()
		if len(bytes.TrimSpace(dirtyOut)) == 0 {
			return nil, nil
		}
	}

	wtPath, cleanup, err := repository.NewWorktree(ctx, o.repo, sha)
	if err != nil {
		return nil, fmt.Errorf("create worktree for release %s (%s): %w", resolvedRef, sha, err)
	}

	o.repo = wtPath
	return cleanup, nil
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
		ID:              caseID,
		TicketID:        o.ticketID,
		TicketComponent: o.ticketComp,
		TicketRelease:   o.ticketRel,
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
	c.NonLocusBasis = o.nonLocusBasis
	c.AcceptLocusProposals = o.acceptLocusProposals
	c.StrictLLM = o.strictLLM
	if o.cveAnalysis != "" {
		c.CVEAnalysisProfile = domain.AnalysisProfile(o.cveAnalysis)
	} else {
		c.CVEAnalysisProfile = domain.ProfileOff
	}
	if o.nonLocusFile != "" {
		b, err := os.ReadFile(o.nonLocusFile)
		if err != nil {
			return nil, fmt.Errorf("read non-locus basis: %w", err)
		}
		if err := json.Unmarshal(b, &c.NonLocusBasis); err != nil {
			return nil, fmt.Errorf("non-locus basis file is invalid: %w", err)
		}
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
	if o.worktreeRef != "" && o.checkoutRel {
		shortSHA := o.worktreeSHA
		if len(shortSHA) > 8 {
			shortSHA = shortSHA[:8]
		}
		c.EvidenceGraph.AddLimitation(fmt.Sprintf(
			"checkout release: %s (%s)", o.worktreeRef, shortSHA))
	}

	srcIndex := o.srcIndex
	if srcIndex == nil {
		srcIndex = &goanalysis.Index{
			Dir: absRepo,
			Env: tc.Env,
			KB:  o.kb,
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
	if o.strictLLM && (!llmCfg.Enabled || o.detOnly) {
		return nil, fmt.Errorf("strict-llm: cannot use --strict-llm when LLM is disabled or --deterministic-only is set")
	}
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
		evaluator.MissingCall{},
		evaluator.Exposure{},
		evaluator.Authentication{},
		evaluator.ConfigFlag{},
		evaluator.Presence{},
		evaluator.VersionFact{},
		evaluator.Platform{},
		// Last resort: unrouted CUSTOM conditions (check= shapes are
		// claimed by their own evaluators above).
		evaluator.Custom{},
	}
	var fallbackEval evaluator.ConditionEvaluator
	var gapPlanner states.HypothesisPlanner
	var llmClient *llm.Client
	if llmCfg.Enabled && !o.detOnly {
		client := llm.NewClient(llmCfg)
		llmClient = client
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
				TrustedPeer:      o.trustedPeer,
			},
		},
		states.ResolveVulnerability{Source: src, ID: o.vulnID},
		states.CheckAffected{Resolver: affected.GoResolver{Tool: goTool}},
		states.ResolveRootCause{
			Manual:    append(o.manualRC, parseRootCauses(o.rootCauseArgs)...),
			Resolver:  rcResolver,
			Verifier:  &rootcause.Verifier{Source: srcIndex},
			LLMClient: llmClient,
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
		states.GapAnalysis{Source: srcIndex, Evaluators: conditionEvaluators, Planner: gapPlanner, Fallback: fallbackEval, AllowExec: o.allowExec},
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

func printCase(c *domain.AnalysisCase, caseDir string, lang ...string) {
	isRU := len(lang) == 0 || lang[0] != "en"
	fmt.Printf("case: %s\n", c.ID)
	if c.TicketID != "" {
		fmt.Printf("ticket: %s\n", c.TicketID)
	}
	if c.TicketComponent != "" {
		fmt.Printf("component: %s\n", c.TicketComponent)
	}
	fmt.Printf("state: %s\n", c.Workflow.State)
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
	repName := "report.md"
	if !isRU {
		repName = "report.en.md"
	}
	fmt.Printf("report: %s\n", filepath.Join(caseDir, string(c.ID), repName))
	if r := report.TrackerRationale(c); r != "" {
		if isRU {
			fmt.Printf("\n--- Резюме ---\n%s\n--------------\n", r)
		} else {
			fmt.Printf("\n--- Executive Summary ---\n%s\n-------------------------\n", r)
		}
	}
}

type llmCompleterAdapter struct {
	client *llm.Client
	role   llm.ModelRole
}

func (a llmCompleterAdapter) Complete(ctx context.Context, system, user string) (string, error) {
	content, _, err := a.client.Complete(ctx, a.role, system, user)
	return content, err
}

// loadLLMEnv loads the LLM dotenv file: explicit --llm-env wins, else it
// probes .env in the working directory and the analyzed repo.
// Missing files are ignored; malformed lines are skipped. Guarded by
// llmEnvMu: concurrent os.Setenv from parallel scan workers would race.
var (
	llmEnvMu     sync.Mutex
	llmEnvLoaded = make(map[string]bool)
)

func loadLLMEnv(explicit, repo string) {
	llmEnvMu.Lock()
	defer llmEnvMu.Unlock()

	candidates := []string{explicit}
	if explicit == "" {
		candidates = []string{".env"}
		if repo != "" {
			candidates = append(candidates, filepath.Join(repo, ".env"))
		}
	}
	for _, p := range candidates {
		if p == "" || llmEnvLoaded[p] {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			continue
		}
		_ = llm.LoadDotEnv(p)
		llmEnvLoaded[p] = true
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
	var err error
	if o.kb, err = loadKnowledgeBase(o.knowledge); err != nil {
		return err
	}
	budget, err := parseMemLimit(o.memLimit)
	if err != nil {
		return err
	}
	ctx, stop := applyMemoryLimit(context.Background(), budget)
	defer stop()

	wtCleanup, err := prepareReleaseWorktree(ctx, &o)
	if err != nil {
		return err
	}
	if wtCleanup != nil {
		defer wtCleanup()
	}

	absRepo, err := filepath.Abs(o.repo)
	if err != nil {
		return err
	}

	// Resolve the target toolchain once — shared tools run under it.
	o.toolchain, o.tcLims = resolveToolchain(ctx, o)

	// Shared per-scan resources: one source index, one go list, one
	// govulncheck run — repeated per-advisory otherwise.
	o.goTool = affected.CachingTool(affected.ExecGoTool{Bin: o.toolchain.GoBin, Env: o.toolchain.Env})
	o.gvRunner = goanalysis.CachingRunner(goanalysis.ExecRunner{Env: o.toolchain.Env})
	o.srcIndex = &goanalysis.Index{
		Dir: absRepo,
		Env: o.toolchain.Env,
		KB:  o.kb,
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
		TrustedPeer: o.trustedPeer,
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
		if len(r.CheckedModules) > 0 {
			return fmt.Sprintf("none of the affected module(s) %s resolve to a product dependency (go list -m all)",
				strings.Join(r.CheckedModules, ", "))
		}
		return "vulnerable module is not part of the product dependency graph"
	case r.VersionAffected == domain.ClaimFalse:
		if r.ResolvedVersion != "" {
			return fmt.Sprintf("resolved version %s is outside the affected range", r.ResolvedVersion)
		}
		return "resolved dependency version is outside affected range"
	case r.PackagePresent == domain.ClaimFalse:
		if len(r.CheckedPackages) > 0 {
			return fmt.Sprintf("affected package(s) %s are absent from the product's transitive import closure (go list -deps -test ./...) — the code is not linked into the product",
				strings.Join(r.CheckedPackages, ", "))
		}
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
