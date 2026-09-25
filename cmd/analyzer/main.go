package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"example.com/vuln-analyzer/internal/affected"
	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/evaluator"
	"example.com/vuln-analyzer/internal/exploit"
	"example.com/vuln-analyzer/internal/fix"
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/persistence/filesystem"
	"example.com/vuln-analyzer/internal/repository"
	"example.com/vuln-analyzer/internal/review"
	"example.com/vuln-analyzer/internal/rootcause"
	"example.com/vuln-analyzer/internal/states"
	"example.com/vuln-analyzer/internal/tracker"
	"example.com/vuln-analyzer/internal/vulnerability"
	"example.com/vuln-analyzer/internal/workflow"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "analyze" {
		usage()
	}
	if err := runAnalyze(os.Args[2:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  vuln-analyzer analyze --repo <path> --vuln <GO-/CVE-/GHSA-id> [options]

options:
  --vuln-file <path>     load advisory from local OSV JSON instead of api.osv.dev
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

func runAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	repo := fs.String("repo", "", "path to Go repository")
	vulnID := fs.String("vuln", "", "vulnerability id (GO-/CVE-/GHSA-)")
	vulnFile := fs.String("vuln-file", "", "local OSV JSON file")
	osvURL := fs.String("osv-url", "", "OSV API base URL")
	caseDir := fs.String("case-dir", ".vuln-analyzer", "case state directory")
	goos := fs.String("goos", "", "target GOOS")
	goarch := fs.String("goarch", "", "target GOARCH")
	tags := fs.String("build-tags", "", "comma-separated build tags")
	exploitModelPath := fs.String("exploit-model", "", "manual exploit model JSON")
	deterministicOnly := fs.Bool("deterministic-only", false, "disable LLM-backed states")
	var rootCauseFlags stringList
	fs.Var(&rootCauseFlags, "root-cause", "manual root cause as pkg/path.Symbol (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *repo == "" || *vulnID == "" {
		usage()
	}
	absRepo, err := filepath.Abs(*repo)
	if err != nil {
		return err
	}

	var src vulnerability.Source
	if *vulnFile != "" {
		src = vulnerability.FileSource{Path: *vulnFile}
	} else {
		src = vulnerability.OSVSource{BaseURL: *osvURL}
	}

	store := filesystem.New(*caseDir)
	caseID := domain.CaseID(fmt.Sprintf("%s-%d", sanitizeID(*vulnID), time.Now().Unix()))
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
	if *deterministicOnly {
		c.EvidenceGraph.Limitations = append(c.EvidenceGraph.Limitations,
			"deterministic-only mode: LLM-backed states resolve to INCONCLUSIVE")
	}
	if err := store.Create(context.Background(), c); err != nil {
		return err
	}

	srcIndex := &goanalysis.Index{
		Dir: absRepo,
		Build: domain.ProductSnapshot{
			GOOS: *goos, GOARCH: *goarch, BuildTags: splitCSV(*tags),
		},
	}

	engine := workflow.New(store,
		states.Created{},
		states.SnapshotProduct{
			Repo: repository.Service{},
			Path: absRepo,
			Options: repository.SnapshotOptions{
				GOOS:      *goos,
				GOARCH:    *goarch,
				BuildTags: splitCSV(*tags),
			},
		},
		states.ResolveVulnerability{Source: src, ID: *vulnID},
		states.CheckAffected{Resolver: affected.GoResolver{}},
		states.ResolveRootCause{
			Manual:   parseRootCauses(rootCauseFlags),
			Resolver: &rootcause.Resolver{Fix: fix.Resolver{}, Patch: fix.HTTPProvider{}},
			Verifier: &rootcause.Verifier{Source: srcIndex},
		},
		states.BuildExploitModel{
			ModelPath: *exploitModelPath,
			Builder:   &exploit.Builder{Source: srcIndex},
		},
		states.CollectEvidence{
			Govulncheck: goanalysis.ExecRunner{},
			Source:      srcIndex,
		},
		states.EvaluateConditions{Evaluators: []evaluator.ConditionEvaluator{
			evaluator.SymbolReachable{},
			evaluator.ArgumentOrigin{},
		}},
		states.NegativeCheck{Verifier: &goanalysis.Verifier{Source: srcIndex}},
		states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}},
		states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}},
		states.BuildReport{Dir: filepath.Join(*caseDir, string(caseID)),
			Tracker: tracker.FileSink{Dir: filepath.Join(*caseDir, string(caseID))}},
	)

	if err := engine.Run(context.Background(), c); err != nil {
		return fmt.Errorf("workflow: %w", err)
	}

	fmt.Printf("case: %s\nstate: %s\n", c.ID, c.Workflow.State)
	if c.Verdict != nil {
		fmt.Printf("verdict: %s\nreason: %s\n", c.Verdict.Verdict, c.Verdict.Reason)
	}
	fmt.Printf("report: %s\n", filepath.Join(*caseDir, string(caseID), "report.md"))
	return nil
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
