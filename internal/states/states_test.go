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
	"example.com/vuln-analyzer/internal/goanalysis"
	"example.com/vuln-analyzer/internal/persistence/filesystem"
	"example.com/vuln-analyzer/internal/repository"
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
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/product\n\ngo 1.23\n")
	write("main.go", "package main\n\nfunc main() {}\n")
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
	e := workflow.New(store,
		states.Created{},
		states.SnapshotProduct{Repo: repository.Service{}, Path: d.RepoPath},
		states.ResolveVulnerability{Source: d.VulnSrc, ID: d.VulnID},
		states.CheckAffected{Resolver: d.Resolver},
		states.ResolveRootCause{Manual: d.ManualRC},
		states.BuildExploitModel{ModelPath: d.Model},
		states.CollectEvidence{Govulncheck: d.Govulncheck},
		states.EvaluateConditions{Evaluators: []evaluator.ConditionEvaluator{evaluator.SymbolReachable{}}},
		states.NegativeCheck{},
		states.Review{},
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
