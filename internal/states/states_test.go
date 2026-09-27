package states_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
	"example.com/vuln-analyzer/internal/toolaudit"
	"example.com/vuln-analyzer/internal/vulnerability"
	"example.com/vuln-analyzer/internal/workflow"
)

const xnetOSV = `{
  "id": "GO-2024-2687",
  "aliases": ["CVE-2024-45338"],
  "summary": "Non-linear parsing in golang.org/x/net/html",
  "affected": [{
    "package": {"name": "golang.org/x/net", "ecosystem": "Go"},
    "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "0.33.0"}]}],
    "ecosystem_specific": {"imports": [{"path": "golang.org/x/net/html", "symbols": ["Parse"]}]}
  }]
}`

func initRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	return initGit(t, dir)
}

// initRepoFrom copies a testdata fixture into a temp dir and git-inits it,
// so the case is bound to a concrete commit as the spec requires.
func initRepoFrom(t *testing.T, fixture string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	src, err := filepath.Abs(filepath.Join("..", "..", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, sub := range []string{fixture, "dep"} {
		fsys := os.DirFS(filepath.Join(src, sub))
		dst := filepath.Join(dir, sub)
		if err := os.MkdirAll(dst, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(dst, fsys); err != nil {
			t.Fatal(err)
		}
	}
	return initGit(t, filepath.Join(dir, fixture))
}

func initGit(t *testing.T, dir string) string {
	t.Helper()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err != nil {
		write("go.mod", "module example.com/product\n\ngo 1.23\n")
		write("main.go", "package main\n\nfunc main() {}\n")
	}
	for _, args := range [][]string{
		{"git", "init", "-q"},
		{"git", "add", "."},
		{"git", "-c", "user.email=test@test", "-c", "user.name=test", "commit", "-qm", "init"},
	} {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	return dir
}

type engineDeps struct {
	RepoPath    string
	VulnSrc     vulnerability.Source
	VulnID      string
	Resolver    affected.Resolver
	ManualRC    []domain.RootCause
	Model       string
	CaseDir     string
	Govulncheck goanalysis.Runner
	UseSource   bool                     // wire the go/packages source index + verifier
	RCResolver  states.RootCauseResolver // overrides default rootcause.Resolver
}

func runEngine(t *testing.T, d engineDeps) *domain.AnalysisCase {
	t.Helper()
	store := filesystem.New(d.CaseDir)
	c := &domain.AnalysisCase{
		ID: domain.CaseID("test-" + d.VulnID),
		Workflow: domain.WorkflowStatus{
			State:     domain.StateCreated,
			StartedAt: time.Now().UTC(),
			Limits:    domain.AnalysisLimits{MaxIterations: 64},
		},
	}
	c.EvidenceGraph.Version = "1"
	if err := store.Create(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	var srcIndex *goanalysis.Index
	if d.UseSource {
		srcIndex = &goanalysis.Index{Dir: d.RepoPath}
	}
	rc := states.ResolveRootCause{Manual: d.ManualRC}
	if d.UseSource {
		rc.Resolver = &rootcause.Resolver{Fix: fix.Resolver{}}
		rc.Verifier = &rootcause.Verifier{Source: srcIndex}
	}
	if d.RCResolver != nil {
		rc.Resolver = d.RCResolver
	}
	e := workflow.New(store,
		states.Created{},
		states.SnapshotProduct{Repo: repository.Service{}, Path: d.RepoPath},
		states.ResolveVulnerability{Source: d.VulnSrc, ID: d.VulnID},
		states.CheckAffected{Resolver: d.Resolver},
		rc,
		states.BuildExploitModel{ModelPath: d.Model, Builder: exploitBuilder(srcIndex)},
		states.CollectEvidence{Govulncheck: d.Govulncheck, Source: srcIndex},
		states.EvaluateConditions{Evaluators: []evaluator.ConditionEvaluator{
			evaluator.SymbolReachable{},
			evaluator.ArgumentOrigin{},
			evaluator.Validation{},
			evaluator.Exposure{},
			evaluator.ConfigFlag{},
			evaluator.Presence{},
			evaluator.Platform{},
		}},
		states.GapAnalysis{Source: srcIndex, Evaluators: []evaluator.ConditionEvaluator{
			evaluator.SymbolReachable{},
			evaluator.ArgumentOrigin{},
			evaluator.Validation{},
			evaluator.Exposure{},
			evaluator.ConfigFlag{},
			evaluator.Presence{},
			evaluator.Platform{},
		}},
		states.NegativeCheck{Verifier: &goanalysis.Verifier{Source: srcIndex}},
		states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}},
		states.RepairAnalysis{},
		states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}},
		states.BuildReport{Dir: filepath.Join(d.CaseDir, string(c.ID))},
	)
	ctx := toolaudit.WithRecorder(context.Background(),
		&toolaudit.Recorder{Sink: c.EvidenceGraph.AddToolExecution})
	if err := e.Run(ctx, c); err != nil {
		t.Fatal(err)
	}
	return c
}

// Every real subprocess the pipeline spawns must land in the case's
// tool_executions audit trail (spec §22): at minimum the snapshot's
// git rev-parse and `go version` probes.
func TestE2EToolExecutionsRecorded(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	if err := os.WriteFile(vulnPath, []byte(xnetOSV), 0o644); err != nil {
		t.Fatal(err)
	}
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-2024-3333",
		Resolver: stubResolver{},
		CaseDir:  filepath.Join(dir, "cases"),
	})
	tools := map[string]bool{}
	for _, tx := range c.EvidenceGraph.ToolExecutions {
		tools[tx.Tool] = true
		if tx.ID == "" {
			t.Fatalf("execution without id: %+v", tx)
		}
		if tx.Tool == "git" && (tx.ExitCode != 0 || tx.StdoutSHA256 == "") {
			t.Fatalf("bad git record: %+v", tx)
		}
	}
	if !tools["git"] || !tools["go"] {
		t.Fatalf("want git+go executions recorded, got %v", c.EvidenceGraph.ToolExecutions)
	}
}

// Golden case: module absent from the dependency graph -> NOT_AFFECTED,
// reached entirely by deterministic tooling.
func TestE2ENotAffected(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	if err := os.WriteFile(vulnPath, []byte(xnetOSV), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-2024-2687",
		Resolver: affected.GoResolver{},
		CaseDir:  caseDir,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNotAffected {
		t.Fatalf("verdict=%+v", c.Verdict)
	}
	if c.Affected == nil || c.Affected.ModulePresent != domain.ClaimFalse {
		t.Fatalf("affected=%+v", c.Affected)
	}
	if len(c.EvidenceGraph.Evidence) == 0 || c.EvidenceGraph.Hash == "" {
		t.Fatal("evidence graph must contain the go list artifact and a hash")
	}
	for _, f := range []string{"report.json", "report.md"} {
		if _, err := os.Stat(filepath.Join(caseDir, string(c.ID), f)); err != nil {
			t.Fatalf("missing report artifact %s: %v", f, err)
		}
	}
}

// Affected dependency without any root cause input must not silently pass:
// the case terminates INCONCLUSIVE.
func TestE2EAffectedNoRootCause(t *testing.T) {
	repo := initRepo(t)
	caseDir := t.TempDir()

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/product"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		CaseDir:  caseDir,
	})
	if c.Workflow.State != domain.StateInconclusive {
		t.Fatalf("state=%s, want INCONCLUSIVE", c.Workflow.State)
	}
}

// Manual root cause + manual exploit model still cannot reach a verdict
// without evidence collectors: every condition stays UNKNOWN.
func TestE2EManualModelStaysInconclusive(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	model := domain.ExploitModel{
		Impact: "test",
		MandatoryConditions: []domain.Condition{
			{ID: "C-REACH", Kind: domain.ConditionSymbolReachable, Mandatory: true, Description: "symbol reachable"},
		},
	}
	mb, _ := json.Marshal(model)
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, mb, 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/product"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/product", Symbol: "main", Role: domain.RootCauseSink}},
		Model:    mp,
		CaseDir:  caseDir,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%+v, want INCONCLUSIVE", c.Verdict)
	}
	if len(c.Claims) != 1 || c.Claims[0].Result != domain.ClaimUnknown {
		t.Fatalf("claims=%+v, want one UNKNOWN", c.Claims)
	}
}

// SYMBOL_REACHABLE happy path: govulncheck reports a call path to the
// root-cause symbol -> claim TRUE. Remaining conditions stay UNKNOWN so the
// verdict is INCONCLUSIVE, not EXPLOITABLE.
func TestE2ESymbolReachableTrue(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,"description":"Parse reachable"},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,"description":"attacker controls input"}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/product","package":"example.com/product","function":"main","position":{"filename":"/repo/main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"/dep/vuln/vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink}},
		Model:    mp,
		CaseDir:  caseDir,
		Govulncheck: fakeGovulncheck{
			out: []byte(gv),
		},
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	if len(c.EvidenceGraph.CallPaths) != 1 {
		t.Fatalf("call paths=%+v", c.EvidenceGraph.CallPaths)
	}
	claim := findClaimT(t, c.Claims, "C-REACH")
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("C-REACH=%s want TRUE (claim=%+v)", claim.Result, claim)
	}
	if len(claim.EvidenceIDs) == 0 {
		t.Fatal("TRUE claim must cite evidence")
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%+v want INCONCLUSIVE (C-INPUT unresolved)", c.Verdict)
	}
}

// govulncheck ran clean and found no call path -> candidate FALSE ->
// negative verification unavailable -> INCONCLUSIVE, never NO_EXPLOIT_PATH_FOUND.
func TestE2ENoPathStaysInconclusive(t *testing.T) {
	repo := initRepo(t)
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,"description":"Parse reachable"}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:    mp,
		CaseDir:  caseDir,
		Govulncheck: fakeGovulncheck{
			out: []byte(`{"protocol_version":"v1.0.0"}`),
		},
	})

	// No module-usage scan is configured in this engine, so the absence of
	// call sites is not evidence: C-REACH stays UNKNOWN, never FALSE.
	claim := findClaimT(t, c.Claims, "C-REACH")
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("C-REACH=%s want UNKNOWN (no usage scan ran)", claim.Result)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%+v want INCONCLUSIVE", c.Verdict)
	}
}

func findClaimT(t *testing.T, claims []domain.Claim, id domain.ConditionID) domain.Claim {
	t.Helper()
	for _, cl := range claims {
		if cl.ConditionID == id {
			return cl
		}
	}
	t.Fatalf("claim for %s not found: %+v", id, claims)
	return domain.Claim{}
}

type fakeGovulncheck struct {
	out []byte
	err error
}

func (f fakeGovulncheck) RunGovulncheck(context.Context, string, domain.ProductSnapshot) ([]byte, error) {
	return f.out, f.err
}

type stubResolver struct{}

func (stubResolver) Resolve(context.Context, domain.Vulnerability, domain.ProductSnapshot) (domain.AffectedResult, []domain.Evidence, error) {
	return domain.AffectedResult{
		ModulePresent:   domain.ClaimTrue,
		ResolvedVersion: "v1.0.0",
		VersionAffected: domain.ClaimTrue,
		PackagePresent:  domain.ClaimTrue,
		BuildRelevant:   domain.ClaimTrue,
	}, nil, nil
}

// Slice 3 golden: the vulnerable symbol IS reachable (govulncheck trace) but
// the only call site passes a constant argument. ATTACKER_CONTROL goes FALSE,
// negative verification confirms every call site is non-external, and the
// verdict is NO_EXPLOIT_PATH_FOUND — the first verified-safe path.
func TestE2EConstantInputVerifiedFalse(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/constprod","package":"example.com/constprod","function":"main","position":{"filename":"main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	claim := findClaimT(t, c.Claims, "C-INPUT")
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("C-INPUT=%s want FALSE", claim.Result)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("neg verification=%+v want VERIFIED", claim.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
	if len(c.EvidenceGraph.DataFlows) == 0 {
		t.Fatal("expected provenance data flows in evidence graph")
	}
}

// External input at the sink argument -> ATTACKER_CONTROL TRUE -> with
// reachability also TRUE the deterministic verdict is EXPLOITABLE.
func TestE2EExternalInputTrue(t *testing.T) {
	repo := initRepoFrom(t, "extprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/extprod","package":"example.com/extprod","function":"main","position":{"filename":"main.go","line":10}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})

	claim := findClaimT(t, c.Claims, "C-INPUT")
	if claim.Result != domain.ClaimTrue {
		t.Fatalf("C-INPUT=%s want TRUE", claim.Result)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
	}
}

// Function-value escape: govulncheck reports no call path (FALSE candidate)
// but ScanDynamic finds `f := vuln.Parse` — the falsification pass demotes
// FALSE to UNKNOWN and the verdict stays INCONCLUSIVE, honoring the invariant
// that absence of evidence is not absence of exploitability.
func TestE2EFuncValueDemotesFalse(t *testing.T) {
	repo := initRepoFrom(t, "funcvalprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}`)},
		UseSource:   true,
	})

	claim := findClaimT(t, c.Claims, "C-REACH")
	if claim.Result != domain.ClaimUnknown {
		t.Fatalf("C-REACH=%s want UNKNOWN after contradiction", claim.Result)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeContradicted {
		t.Fatalf("neg verification=%+v want CONTRADICTED", claim.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%+v want INCONCLUSIVE", c.Verdict)
	}
}

// Slice 4 golden: no --root-cause flag — the pipeline derives the root cause
// from advisory affected symbols (AUTHORITATIVE evidence) and verifies the
// symbol exists in the dependency source. Same verdict path as the manual
// constprod case.
func TestE2EAutoRootCause(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	osv := `{"id":"GO-TEST-AUTO","summary":"auto rc",
 "affected":[{"package":{"name":"example.com/dep","ecosystem":"Go"},
  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}],
  "ecosystem_specific":{"imports":[{"path":"example.com/dep/vuln","symbols":["Parse"]}]}}],
 "references":[{"type":"ADVISORY","url":"https://example.com/adv"}]}`
	if err := os.WriteFile(vulnPath, []byte(osv), 0o644); err != nil {
		t.Fatal(err)
	}
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-AUTO","fixed_version":"v1.0.1","trace":[
 {"module":"example.com/constprod","package":"example.com/constprod","function":"main","position":{"filename":"main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-TEST-AUTO",
		Resolver: stubResolver{},
		// no ManualRC — resolved automatically
		Model:       mp,
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	if c.RootCause == nil || c.RootCause.Status != domain.RootCauseResolved {
		t.Fatalf("rootcause=%+v", c.RootCause)
	}
	if len(c.RootCause.RootCauses) != 1 || c.RootCause.RootCauses[0].Symbol != "Parse" {
		t.Fatalf("root causes=%+v", c.RootCause.RootCauses)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

func exploitBuilder(ix *goanalysis.Index) *exploit.Builder {
	if ix == nil {
		return nil
	}
	return &exploit.Builder{Source: ix}
}

// Slice 5 golden: fully automatic — no --root-cause, no --exploit-model.
// The builder derives mandatory conditions from the resolved root cause;
// on constprod the same verified-FALSE path yields NO_EXPLOIT_PATH_FOUND.
func TestE2EAutoExploitModel(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	vulnPath := filepath.Join(dir, "vuln.json")
	osv := `{"id":"GO-TEST-AUTO","summary":"auto model",
 "affected":[{"package":{"name":"example.com/dep","ecosystem":"Go"},
  "ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}],
  "ecosystem_specific":{"imports":[{"path":"example.com/dep/vuln","symbols":["Parse"]}]}}],
 "references":[{"type":"ADVISORY","url":"https://example.com/adv"}]}`
	if err := os.WriteFile(vulnPath, []byte(osv), 0o644); err != nil {
		t.Fatal(err)
	}
	caseDir := filepath.Join(dir, "cases")

	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-AUTO","fixed_version":"v1.0.1","trace":[
 {"module":"example.com/constprod","package":"example.com/constprod","function":"main","position":{"filename":"main.go","line":9}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc:  vulnerability.FileSource{Path: vulnPath},
		VulnID:   "GO-TEST-AUTO",
		Resolver: stubResolver{},
		CaseDir:  caseDir,
		// no ManualRC, no Model — both derived automatically
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})

	if c.Workflow.State != domain.StateCompleted {
		t.Fatalf("state=%s reason=%s", c.Workflow.State, c.Workflow.Reason)
	}
	if c.Exploit == nil || len(c.Exploit.MandatoryConditions) == 0 {
		t.Fatal("expected auto-built exploit model")
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

func TestReviewDemotesUnsupportedTrue(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{ID: "C-1", Kind: domain.ConditionSymbolReachable}},
		},
		RootCause: &domain.RootCauseModel{Status: domain.RootCauseResolved},
		Claims: []domain.Claim{{
			ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue,
		}},
	}
	h := states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}}
	tr, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateRepairAnalysis {
		t.Fatalf("next = %s, want REPAIR_ANALYSIS", tr.Next)
	}
	if len(c.Reviews) != 1 || c.Reviews[0].Result != domain.ReviewRevise {
		t.Fatalf("reviews: %+v", c.Reviews)
	}
	// The claim is still TRUE until the repair state runs.
	if c.Claims[0].Result != domain.ClaimTrue {
		t.Fatalf("claim demoted inside REVIEW, before repair: %s", c.Claims[0].Result)
	}
	tr, err = states.RepairAnalysis{}.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("next = %s, want re-REVIEW after repair", tr.Next)
	}
	if c.Claims[0].Result != domain.ClaimUnknown {
		t.Fatalf("claim not demoted: %s", c.Claims[0].Result)
	}
	if len(c.Claims[0].Limitations) == 0 {
		t.Fatal("demotion must record a limitation")
	}
}

func TestReviewBudgetExhausted(t *testing.T) {
	c := &domain.AnalysisCase{
		Reviews: []domain.Review{{Result: domain.ReviewRevise}, {Result: domain.ReviewRevise}},
		Workflow: domain.WorkflowStatus{
			Limits: domain.AnalysisLimits{MaxReviewIterations: 2},
		},
	}
	h := states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}}
	tr, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next = %s", tr.Next)
	}
	found := false
	for _, l := range c.EvidenceGraph.Limitations {
		if l == "review iteration budget exhausted; verdict computed on repaired claims" {
			found = true
		}
	}
	if !found {
		t.Fatal("budget limitation not recorded")
	}
}

// Tool failure is never negative evidence: a govulncheck error must not
// fabricate a FALSE on C-REACH. Positive evidence still counts though —
// extprod directly calls the sink, so module-usage evidence produces TRUE
// with a limitation even when govulncheck itself failed.
func TestE2EGovulncheckFailureStaysInconclusive(t *testing.T) {
	// extprod passes os.Args into the sink: C-INPUT is TRUE, so the only
	// path to a non-INCONCLUSIVE verdict would be a fabricated FALSE on
	// C-REACH — the bug this test guards against.
	repo := initRepoFrom(t, "extprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{err: fmt.Errorf("govulncheck: binary missing")},
		UseSource:   true,
	})
	for _, cl := range c.Claims {
		if cl.ConditionID == "C-REACH" && cl.Result == domain.ClaimFalse {
			t.Fatal("tool failure produced a FALSE claim")
		}
	}
	// Module-usage evidence made C-REACH legitimately TRUE — with C-INPUT
	// also TRUE the verdict is EXPLOITABLE despite the govulncheck failure.
	reach := findClaimT(t, c.Claims, "C-REACH")
	if reach.Result != domain.ClaimTrue {
		t.Fatalf("C-REACH=%s want TRUE via module usage", reach.Result)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
	}
}

// Deployment-dependent provenance: a flag-fed sink argument is neither
// provably safe nor provably attacker-controlled — the claim must stay
// UNKNOWN and the case INCONCLUSIVE (spec §12: no silent default-config
// generalization).
func TestE2EConfigInputStaysUnknown(t *testing.T) {
	repo := initRepoFrom(t, "configprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/configprod","package":"example.com/configprod","function":"main","position":{"filename":"main.go","line":17}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var input *domain.Claim
	for i := range c.Claims {
		if c.Claims[i].ConditionID == "C-INPUT" {
			input = &c.Claims[i]
		}
	}
	if input == nil || input.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%+v want UNKNOWN", input)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%+v", c.Verdict)
	}
}

// Database-populated input is neither attacker-controlled nor safe:
// DATABASE provenance -> deploy-dependent UNKNOWN -> INCONCLUSIVE.
func TestE2EDatabaseOriginStaysUnknown(t *testing.T) {
	repo := initRepoFrom(t, "dbprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/dbprod","package":"example.com/dbprod","function":"main","position":{"filename":"main.go","line":19}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var sawDB bool
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.Origin == domain.OriginDatabase {
			sawDB = true
		}
	}
	if !sawDB {
		t.Fatalf("no DATABASE flow recorded; flows=%+v", c.EvidenceGraph.DataFlows)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	if input.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%s want UNKNOWN (database is deploy-dependent)", input.Result)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%+v want INCONCLUSIVE", c.Verdict)
	}
}

// A configured internal-service endpoint produces INTERNAL_SERVICE
// provenance: not externally attacker-controlled, not constant —
// deploy-dependent UNKNOWN -> INCONCLUSIVE.
func TestE2EInternalServiceOriginStaysUnknown(t *testing.T) {
	repo := initRepoFrom(t, "svcprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/svcprod","package":"example.com/svcprod","function":"main","position":{"filename":"main.go","line":21}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var sawSvc bool
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.Origin == domain.OriginInternalService {
			sawSvc = true
		}
	}
	if !sawSvc {
		t.Fatalf("no INTERNAL_SERVICE flow recorded; flows=%+v", c.EvidenceGraph.DataFlows)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	if input.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%s want UNKNOWN (internal service is deploy-dependent)", input.Result)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%+v want INCONCLUSIVE", c.Verdict)
	}
}

// Three-hop parameter chain — deeper than the default provenance bound.
// The gap-analysis loop must record a CONFIRMED hypothesis and resolve
// the argument origin to EXTERNAL, flipping C-INPUT to TRUE.
func TestE2EGapAnalysisDeepTrace(t *testing.T) {
	repo := initRepoFrom(t, "deepprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/deepprod","package":"example.com/deepprod","function":"level3","position":{"filename":"main.go","line":24}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var confirmed bool
	for _, h := range c.Hypotheses {
		if h.Status == domain.HypothesisConfirmed {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatalf("no CONFIRMED hypothesis recorded; hypotheses=%+v", c.Hypotheses)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	if input.Result != domain.ClaimTrue {
		t.Fatalf("C-INPUT=%s want TRUE (deep trace resolved external)", input.Result)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
	}
}

// Advisory names a symbol that does not exist in the dependency source:
// all candidates fail verification -> AMBIGUOUS -> INCONCLUSIVE.
func TestE2EAmbiguousRootCause(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {
				ID:     "GO-TEST-1",
				Module: "example.com/dep",
				AffectedPackages: []domain.AffectedPackage{{
					Path:    "example.com/dep/vuln",
					Symbols: []string{"Nonexistent"},
				}},
				AffectedSymbols: []domain.SymbolRef{
					{Package: "example.com/dep/vuln", Symbol: "Nonexistent"},
				},
			},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}`)},
		UseSource:   true,
	})
	if c.RootCause == nil || c.RootCause.Status != domain.RootCauseAmbiguous {
		t.Fatalf("root cause=%+v", c.RootCause)
	}
	if c.Workflow.State != domain.StateInconclusive {
		t.Fatalf("state=%s", c.Workflow.State)
	}
}

// A resolver whose verified-failed candidates get a second chance via
// the RootCauseProposer hook; proposals pass through the same verifier.
type retryResolver struct{ proposed bool }

func (r *retryResolver) Resolve(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability) (*domain.RootCauseModel, []domain.Evidence, error) {
	return &domain.RootCauseModel{
		Status: domain.RootCauseResolved,
		RootCauses: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "AddedOnlyByFix",
			Role: domain.RootCauseSink, Mechanism: "fix-commit candidate",
		}},
	}, nil, nil
}

func (r *retryResolver) Propose(_ context.Context, _ *domain.AnalysisCase, _ domain.Vulnerability) ([]domain.RootCause, []string, error) {
	r.proposed = true
	return []domain.RootCause{{
		Package: "example.com/dep/vuln", Symbol: "Parse",
		Role: domain.RootCauseSink, Mechanism: "retry proposal",
	}}, nil, nil
}

// Fix commits may name symbols that only exist post-fix; verification
// drops them -> the Proposer hook supplies a verified replacement.
func TestRootCauseRetryOnVerificationFailure(t *testing.T) {
	repo := initRepoFrom(t, "constprod")
	dir := t.TempDir()
	res := &retryResolver{}
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-2": {
				ID:     "GO-TEST-2",
				Module: "example.com/dep",
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"Parse"},
				}},
			},
		}},
		VulnID:      "GO-TEST-2",
		Resolver:    stubResolver{},
		RCResolver:  res,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}`)},
		UseSource:   true,
	})
	if !res.proposed {
		t.Fatal("Propose was never called despite verification failure")
	}
	if c.RootCause == nil || c.RootCause.Status != domain.RootCauseResolved {
		t.Fatalf("root cause=%+v", c.RootCause)
	}
	if len(c.RootCause.RootCauses) != 1 || c.RootCause.RootCauses[0].Symbol != "Parse" {
		t.Fatalf("root causes=%+v", c.RootCause.RootCauses)
	}
}

// Pattern-library golden: the advisory names a credential carrier, not an
// input->sink path. Classified INFO_LEAK, the model is C-DATA-PRESENT +
// C-EXPOSED; with no product reader the pair resolves to a verified FALSE
// -> NO_EXPLOIT_PATH_FOUND.
func TestE2EInfoLeakNoReader(t *testing.T) {
	repo := initRepoFrom(t, "leakprod")
	caseDir := t.TempDir()

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-LEAK-1": {
				ID:      "GO-LEAK-1",
				Module:  "example.com/dep",
				Summary: "credentials retained in plaintext in exported struct fields",
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"PlainAuth.Password"},
				}},
			},
		}},
		VulnID:   "GO-LEAK-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "PlainAuth.Password", Role: domain.RootCauseSink,
		}},
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}`)},
		UseSource:   true,
	})

	if c.Exploit == nil || c.Exploit.Class != "INFO_LEAK" {
		t.Fatalf("exploit class=%v, want INFO_LEAK", c.Exploit)
	}
	present := findClaimT(t, c.Claims, "C-DATA-PRESENT")
	if present.Result != domain.ClaimTrue {
		t.Fatalf("C-DATA-PRESENT=%s want TRUE (%s)", present.Result, present.Explanation)
	}
	exposed := findClaimT(t, c.Claims, "C-EXPOSED")
	if exposed.Result != domain.ClaimFalse {
		t.Fatalf("C-EXPOSED=%s want FALSE (%s)", exposed.Result, exposed.Explanation)
	}
	if exposed.NegativeVerification == nil ||
		exposed.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("neg verification=%+v want VERIFIED", exposed.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

// Same INFO_LEAK model, but the product reads the exported credential
// field: both pattern conditions are TRUE -> EXPLOITABLE.
func TestE2EInfoLeakReader(t *testing.T) {
	repo := initRepoFrom(t, "leakread")
	caseDir := t.TempDir()

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-LEAK-2": {
				ID:      "GO-LEAK-2",
				Module:  "example.com/dep",
				Summary: "credentials retained in plaintext in exported struct fields",
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"PlainAuth.Password"},
				}},
			},
		}},
		VulnID:   "GO-LEAK-2",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "PlainAuth.Password", Role: domain.RootCauseSink,
		}},
		CaseDir:     caseDir,
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}`)},
		UseSource:   true,
	})

	exposed := findClaimT(t, c.Claims, "C-EXPOSED")
	if exposed.Result != domain.ClaimTrue {
		t.Fatalf("C-EXPOSED=%s want TRUE (%s)", exposed.Result, exposed.Explanation)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictExploitable {
		t.Fatalf("verdict=%+v want EXPLOITABLE", c.Verdict)
	}
}

// C-TLS-VERIFY (peer-driven supporting): tlsprod assigns
// InsecureSkipVerify=true — the knob check must resolve TRUE.
func TestE2ETLSKnobInsecure(t *testing.T) {
	repo := initRepoFrom(t, "tlsprod")
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-WIRE-1": {
				ID:      "GO-WIRE-1",
				Module:  "example.com/dep",
				Summary: "wire protocol parser buffer overflow in length handling",
				CWE:     []string{"CWE-787"},
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"Parse"},
				}},
			},
		}},
		VulnID:   "GO-WIRE-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink,
		}},
		CaseDir:     t.TempDir(),
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}`)},
		UseSource:   true,
	})
	cl := findClaimT(t, c.Claims, "C-TLS-VERIFY")
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("C-TLS-VERIFY=%s want TRUE (%s; lims=%v)", cl.Result, cl.Explanation, cl.Limitations)
	}
}

// tlssafe never assigns the knob: bool field + insecure=true → Go
// zero-value FALSE candidate, demoted to INSUFFICIENT_SCOPE by NV.
func TestE2ETLSKnobSafe(t *testing.T) {
	repo := initRepoFrom(t, "tlssafe")
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-WIRE-2": {
				ID:      "GO-WIRE-2",
				Module:  "example.com/dep",
				Summary: "wire protocol parser buffer overflow in length handling",
				CWE:     []string{"CWE-787"},
				AffectedPackages: []domain.AffectedPackage{{
					Path: "example.com/dep/vuln", Symbols: []string{"Parse"},
				}},
			},
		}},
		VulnID:   "GO-WIRE-2",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{
			Package: "example.com/dep/vuln", Symbol: "Parse", Role: domain.RootCauseSink,
		}},
		CaseDir:     t.TempDir(),
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}`)},
		UseSource:   true,
	})
	cl := findClaimT(t, c.Claims, "C-TLS-VERIFY")
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("C-TLS-VERIFY=%s want FALSE (%s; lims=%v)", cl.Result, cl.Explanation, cl.Limitations)
	}
	if cl.NegativeVerification == nil ||
		cl.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("neg verification=%+v want INSUFFICIENT_SCOPE", cl.NegativeVerification)
	}
}

// Caller-frame validation: the sink frame has no guard, but the only
// caller validates the argument before the call. GAP_ANALYSIS climbs the
// caller chain, records a sink-covering guard, and VALIDATION goes FALSE.
func TestE2ECallerFrameGuard(t *testing.T) {
	repo := initRepoFrom(t, "guardprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0},
		{"id":"C-VALID","kind":"VALIDATION","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:    mp,
		CaseDir:  filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","trace":[
 {"package":"example.com/guardprod","function":"sink","position":{"filename":"main.go","line":11}},
 {"package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`)},
		UseSource: true,
	})

	cl := findClaimT(t, c.Claims, "C-VALID")
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("C-VALID=%s want FALSE via caller-frame guard (%s; lims=%v)",
			cl.Result, cl.Explanation, cl.Limitations)
	}
	var cover bool
	for _, v := range c.EvidenceGraph.Validations {
		if v.Covers != nil {
			cover = true
		}
	}
	if !cover {
		t.Fatal("expected a Covers= validation marking caller-frame coverage")
	}
	var hyp *domain.Hypothesis
	for i := range c.Hypotheses {
		if c.Hypotheses[i].ConditionID == "C-VALID" {
			hyp = &c.Hypotheses[i]
		}
	}
	if hyp == nil || hyp.Status != domain.HypothesisConfirmed {
		t.Fatalf("hypothesis=%+v want CONFIRMED", hyp)
	}
	if cl.NegativeVerification == nil ||
		cl.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("neg verification=%+v want VERIFIED", cl.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}

// Partial caller coverage must NOT justify FALSE: one caller guards, the
// other does not — VALIDATION stays UNKNOWN, verdict INCONCLUSIVE.
func TestE2EPartialCallerGuardStaysUnknown(t *testing.T) {
	repo := initRepoFrom(t, "mixguard")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0},
		{"id":"C-VALID","kind":"VALIDATION","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}

	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:   "GO-TEST-1",
		Resolver: stubResolver{},
		ManualRC: []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:    mp,
		CaseDir:  filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(`{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","trace":[
 {"package":"example.com/mixguard","function":"sink","position":{"filename":"main.go","line":10}},
 {"package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`)},
		UseSource: true,
	})

	cl := findClaimT(t, c.Claims, "C-VALID")
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("C-VALID=%s want UNKNOWN on partial caller coverage (%s)", cl.Result, cl.Explanation)
	}
	for _, v := range c.EvidenceGraph.Validations {
		if v.Covers != nil {
			t.Fatalf("partial coverage must not emit Covers= validation: %+v", v)
		}
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictInconclusive {
		t.Fatalf("verdict=%+v want INCONCLUSIVE", c.Verdict)
	}
}

// The REVIEW->REPAIR->REVIEW loop converges: the demoted claim resolves
// the high-severity finding, the second review ACCEPTs, and the case
// proceeds to the verdict computed on the repaired claim set.
func TestReviewRepairLoopConverges(t *testing.T) {
	c := &domain.AnalysisCase{
		Exploit: &domain.ExploitModel{
			MandatoryConditions: []domain.Condition{{ID: "C-1", Kind: domain.ConditionSymbolReachable}},
		},
		RootCause: &domain.RootCauseModel{Status: domain.RootCauseResolved},
		Claims: []domain.Claim{{
			ID: "CL-1", ConditionID: "C-1", Result: domain.ClaimTrue,
		}},
	}
	h := states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}}
	rp := states.RepairAnalysis{}

	tr, err := h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateRepairAnalysis {
		t.Fatalf("next=%s want REPAIR_ANALYSIS", tr.Next)
	}
	tr, err = rp.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateReview {
		t.Fatalf("next=%s want re-REVIEW", tr.Next)
	}
	tr, err = h.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next=%s want EVALUATE_VERDICT after ACCEPT", tr.Next)
	}
	if len(c.Reviews) != 2 || c.Reviews[1].Result != domain.ReviewAccept {
		t.Fatalf("second review should accept the repaired claim set: %+v", c.Reviews)
	}
}

// Multi-step LLM planner: Plan is retried per iteration while it reports an
// attempted step, bounded by maxLLMPlanSteps per condition.
type countingPlanner struct {
	calls  int
	result bool
}

func (p *countingPlanner) Plan(_ context.Context, _ domain.Condition, _ *domain.AnalysisCase) bool {
	p.calls++
	return p.result
}

func TestGapLLMPlannerMultiStepBound(t *testing.T) {
	newCase := func() *domain.AnalysisCase {
		return &domain.AnalysisCase{
			Exploit: &domain.ExploitModel{MandatoryConditions: []domain.Condition{
				{ID: "C-RUNTIME", Kind: domain.ConditionRuntime, Mandatory: true},
			}},
			Claims: []domain.Claim{{ConditionID: "C-RUNTIME", Result: domain.ClaimUnknown}},
		}
	}

	// A planner that always finds more to do is capped at maxLLMPlanSteps.
	p := &countingPlanner{result: true}
	c := newCase()
	c.Workflow.Limits.MaxToolCalls = 0 // unlimited
	if _, err := (states.GapAnalysis{Source: &goanalysis.Index{Dir: t.TempDir()}, Planner: p}).Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if p.calls != 3 {
		t.Fatalf("planner calls=%d want %d (bounded per condition)", p.calls, 3)
	}

	// A planner that reports nothing actionable is asked exactly once.
	p2 := &countingPlanner{result: false}
	c2 := newCase()
	if _, err := (states.GapAnalysis{Source: &goanalysis.Index{Dir: t.TempDir()}, Planner: p2}).Run(context.Background(), c2); err != nil {
		t.Fatal(err)
	}
	if p2.calls != 1 {
		t.Fatalf("planner calls=%d want 1 (no retry on non-attempt)", p2.calls)
	}
}

// An authenticated outbound client produces EXTERNAL_AUTHENTICATED
// provenance — distinct from anonymous EXTERNAL_UNTRUSTED in the evidence,
// while still counting as attacker-capable input (authenticated peers can
// be malicious).
func TestE2EAuthenticatedClientOrigin(t *testing.T) {
	repo := initRepoFrom(t, "authprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/authprod","package":"example.com/authprod","function":"main","position":{"filename":"main.go","line":26}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var sawAuth bool
	for _, f := range c.EvidenceGraph.DataFlows {
		if f.Origin == domain.OriginExternalAuthenticated {
			sawAuth = true
		}
	}
	if !sawAuth {
		t.Fatalf("no EXTERNAL_AUTHENTICATED flow recorded; flows=%+v", c.EvidenceGraph.DataFlows)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	if input.Result != domain.ClaimTrue {
		t.Fatalf("C-INPUT=%s want TRUE (authenticated peer is still attacker-capable)", input.Result)
	}
}

// A security-relevant transform between source and sink is recorded in the
// DataFlow chain and surfaced as a claim limitation — never silently
// treated as a guard.
func TestE2ETransformationChainRecorded(t *testing.T) {
	repo := initRepoFrom(t, "escprod")
	dir := t.TempDir()
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-INPUT","kind":"ATTACKER_CONTROL","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"},"arg_index":0}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/escprod","package":"example.com/escprod","function":"main","position":{"filename":"main.go","line":14}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	var sawEscape bool
	for _, f := range c.EvidenceGraph.DataFlows {
		for _, tx := range f.Transformations {
			if tx.Callee == "html.EscapeString" {
				sawEscape = true
			}
		}
	}
	if !sawEscape {
		t.Fatalf("html.EscapeString not recorded in transformations; flows=%+v", c.EvidenceGraph.DataFlows)
	}
	input := findClaimT(t, c.Claims, "C-INPUT")
	var flagged bool
	for _, l := range input.Limitations {
		if strings.Contains(l, "EscapeString") {
			flagged = true
		}
	}
	if !flagged {
		t.Fatalf("security-relevant transform not flagged; limitations=%v", input.Limitations)
	}
	// An opaque transform honestly breaks the trace: EscapeString's body is
	// not a proven passthrough, so the origin is UNKNOWN — the recorded
	// chain makes that UNKNOWN auditable instead of silent.
	if input.Result != domain.ClaimUnknown {
		t.Fatalf("C-INPUT=%s want UNKNOWN (opaque transform)", input.Result)
	}
}

// A platform fact FALSE is decided by the product snapshot, not code
// scope — negative verification VERIFIED and the verdict is
// NO_EXPLOIT_PATH_FOUND rather than an unresolved INCONCLUSIVE.
func TestE2EPlatformFactFalseVerified(t *testing.T) {
	repo := initRepoFrom(t, "extprod")
	dir := t.TempDir()
	other := "plan9"
	if runtime.GOOS == "plan9" {
		other = "haiku" // keep the mismatch impossible
	}
	model := `{"impact":"t","mandatory_conditions":[
		{"id":"C-REACH","kind":"SYMBOL_REACHABLE","mandatory":true,
		 "subject":{"package":"example.com/dep/vuln","symbol":"Parse"}},
		{"id":"C-PLAT","kind":"PLATFORM_CONDITION","mandatory":true,
		 "description":"exploit requires a different OS",
		 "params":{"goos":"` + other + `"}}
	]}`
	mp := filepath.Join(dir, "model.json")
	if err := os.WriteFile(mp, []byte(model), 0o644); err != nil {
		t.Fatal(err)
	}
	gv := `{"protocol_version":"v1.0.0"}
{"finding":{"osv":"GO-TEST-1","fixed_version":"v1.2.0","trace":[
 {"module":"example.com/extprod","package":"example.com/extprod","function":"main","position":{"filename":"main.go","line":10}},
 {"module":"example.com/dep","package":"example.com/dep/vuln","function":"Parse","position":{"filename":"vuln.go","line":4}}
]}}`
	c := runEngine(t, engineDeps{
		RepoPath: repo,
		VulnSrc: vulnerability.StaticSource{Vulns: map[string]*domain.Vulnerability{
			"GO-TEST-1": {ID: "GO-TEST-1", Module: "example.com/dep"},
		}},
		VulnID:      "GO-TEST-1",
		Resolver:    stubResolver{},
		ManualRC:    []domain.RootCause{{Package: "example.com/dep/vuln", Symbol: "Parse"}},
		Model:       mp,
		CaseDir:     filepath.Join(dir, "cases"),
		Govulncheck: fakeGovulncheck{out: []byte(gv)},
		UseSource:   true,
	})
	plat := findClaimT(t, c.Claims, "C-PLAT")
	if plat.Result != domain.ClaimFalse {
		t.Fatalf("C-PLAT=%s want FALSE", plat.Result)
	}
	if plat.NegativeVerification == nil ||
		plat.NegativeVerification.Status != domain.NegativeVerified {
		t.Fatalf("NV=%+v want VERIFIED", plat.NegativeVerification)
	}
	if c.Verdict == nil || c.Verdict.Verdict != domain.VerdictNoExploitPathFound {
		t.Fatalf("verdict=%+v want NO_EXPLOIT_PATH_FOUND", c.Verdict)
	}
}
