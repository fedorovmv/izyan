package states_test

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
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
	UseSource   bool // wire the go/packages source index + verifier
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
		}},
		states.NegativeCheck{Verifier: &goanalysis.Verifier{Source: srcIndex}},
		states.Review{Reviewer: review.Structural{}, Evaluator: evaluator.VerdictEvaluator{}},
		states.EvaluateVerdict{Evaluator: evaluator.VerdictEvaluator{}},
		states.BuildReport{Dir: filepath.Join(d.CaseDir, string(c.ID))},
	)
	if err := e.Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	return c
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

	claim := findClaimT(t, c.Claims, "C-REACH")
	if claim.Result != domain.ClaimFalse {
		t.Fatalf("C-REACH=%s want candidate FALSE", claim.Result)
	}
	if claim.NegativeVerification == nil || claim.NegativeVerification.Status != domain.NegativeInsufficientScope {
		t.Fatalf("neg verification=%+v want INSUFFICIENT_SCOPE", claim.NegativeVerification)
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
	if tr.Next != domain.StateEvaluateVerdict {
		t.Fatalf("next = %s", tr.Next)
	}
	if len(c.Reviews) != 1 || c.Reviews[0].Result != domain.ReviewRevise {
		t.Fatalf("reviews: %+v", c.Reviews)
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
