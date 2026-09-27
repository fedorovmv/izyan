package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/report"
)

// runRemediate implements `vuln-analyzer remediate`: analyze the case,
// derive the deterministic fix target (smallest fixed version above the
// resolved one), and — only with --apply — run `go get`/`go mod tidy`,
// verify the build (optionally tests), then re-analyze the product.
//
// Without --apply the command is read-only: it prints the plan and the
// commands it would run. --apply mutates go.mod/go.sum, so it is an
// explicit opt-in, never implied by other flags.
func runRemediate(args []string) error {
	fs := flag.NewFlagSet("remediate", flag.ExitOnError)
	var o analyzeOpts
	commonFlags(fs, &o)
	fs.StringVar(&o.vulnID, "vuln", "", "vulnerability id (GO-/CVE-/GHSA-)")
	fs.StringVar(&o.vulnFile, "vuln-file", "", "local OSV JSON file")
	fs.StringVar(&o.exploitModel, "exploit-model", "", "manual exploit model JSON")
	var rootCauseFlags stringList
	fs.Var(&rootCauseFlags, "root-cause", "manual root cause as pkg/path.Symbol (repeatable)")
	apply := fs.Bool("apply", false, "apply the fix (go get/go mod tidy) — mutates go.mod/go.sum")
	runTests := fs.Bool("run-tests", false, "run `go test ./...` after the fix before re-analysis")
	if err := fs.Parse(args); err != nil {
		return err
	}
	o.rootCauseArgs = rootCauseFlags
	if o.repo == "" || o.vulnID == "" {
		usage()
	}
	ctx := context.Background()

	before, err := analyzeCase(ctx, o)
	if err != nil {
		return err
	}
	printCase(before, o.caseDir)

	mod, version, ok := report.FixTarget(before)
	if !ok {
		fmt.Println("remediate: component not affected or module unknown — nothing to plan")
		return nil
	}
	if version == "" {
		fmt.Println("remediate: no fixed version published — manual remediation required")
		return nil
	}
	resolved := before.Affected.ResolvedVersion
	fmt.Printf("remediate: %s %s -> %s\n", mod, resolved, version)
	steps := [][]string{
		{"go", "get", mod + "@" + version},
		{"go", "mod", "tidy"},
		{"go", "build", "./..."},
	}
	if *runTests {
		steps = append(steps, []string{"go", "test", "./..."})
	}
	for _, s := range steps {
		fmt.Println("  plan:", joinArgs(s))
	}
	if !*apply {
		fmt.Println("remediate: dry-run — rerun with --apply to execute")
		return nil
	}
	absRepo, err := filepath.Abs(o.repo)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if err := runRemediateStep(absRepo, s); err != nil {
			return fmt.Errorf("remediate step %q failed: %w", joinArgs(s), err)
		}
	}
	after, err := analyzeCase(ctx, o)
	if err != nil {
		return err
	}
	printCase(after, o.caseDir)
	fmt.Printf("remediate: verdict %s -> %s\n",
		verdictString(before), verdictString(after))
	return nil
}

func runRemediateStep(dir string, cmd []string) error {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Dir = dir
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func verdictString(c *domain.AnalysisCase) string {
	if c == nil || c.Verdict == nil {
		return "NONE"
	}
	return string(c.Verdict.Verdict)
}

func joinArgs(s []string) string {
	out := ""
	for i, a := range s {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
