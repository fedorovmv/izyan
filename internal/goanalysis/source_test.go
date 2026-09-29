package goanalysis

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

var vulnSym = domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Parse"}

func fixture(t *testing.T, name string) *Index {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	ix := &Index{Dir: abs}
	return ix
}

func TestModuleUsageAttributesNestedDependency(t *testing.T) {
	ix := fixture(t, "nestedprod")
	parent, err := ix.ModuleUsage(context.Background(), "example.com/nesteddep")
	if err != nil {
		t.Fatal(err)
	}
	if len(parent) != 1 || parent[0].ModuleOwner != "example.com/nesteddep/v2" {
		t.Fatalf("parent prefix scan must retain foreign-owner site as uncertain: %+v", parent)
	}
	child, err := ix.ModuleUsage(context.Background(), "example.com/nesteddep/v2")
	if err != nil {
		t.Fatal(err)
	}
	if len(child) != 1 || child[0].Callee != "example.com/nesteddep/v2.Child" {
		t.Fatalf("child usage=%+v, want Child call", child)
	}
}

func TestFindCallers(t *testing.T) {
	ix := fixture(t, "constprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 {
		t.Fatalf("callers=%+v", sites)
	}
	if sites[0].Function != "main" {
		t.Fatalf("enclosing=%q", sites[0].Function)
	}
}

func TestFindSymbol(t *testing.T) {
	ix := fixture(t, "constprod")
	cs, err := ix.FindSymbol(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Function != "Parse" || !filepath.IsAbs(cs.File) {
		t.Fatalf("got %+v", cs)
	}
}

func TestTraceArgumentConstant(t *testing.T) {
	ix := fixture(t, "constprod")
	sites, _ := ix.FindCallers(context.Background(), vulnSym)
	flow, ev, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginConstant {
		t.Fatalf("origin=%s want CONSTANT (%s)", flow.Origin, flow.Summary)
	}
	if len(ev) == 0 {
		t.Fatal("expected source evidence")
	}
}

func TestTraceArgumentExternal(t *testing.T) {
	ix := fixture(t, "extprod")
	sites, _ := ix.FindCallers(context.Background(), vulnSym)
	flow, _, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("origin=%s want EXTERNAL_UNTRUSTED (%s)", flow.Origin, flow.Summary)
	}
}

func TestTraceParamHop(t *testing.T) {
	ix := fixture(t, "validprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgument(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	// arg of vuln.Parse in handle(s) is parameter s -> caller passes "abcdef"
	if flow.Origin != domain.OriginConstant {
		t.Fatalf("origin=%s want CONSTANT via caller hop (%s)", flow.Origin, flow.Summary)
	}
}

func TestFindValidations(t *testing.T) {
	ix := fixture(t, "validprod")
	sites, _ := ix.FindCallers(context.Background(), vulnSym)
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(vals) != 1 {
		t.Fatalf("validations=%+v", vals)
	}
	if vals[0].Property != "len(s) < 4" {
		t.Fatalf("property=%q", vals[0].Property)
	}
}

func TestScanDynamicFuncValue(t *testing.T) {
	ix := fixture(t, "funcvalprod")
	markers, err := ix.ScanDynamic(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	var fv bool
	for _, m := range markers {
		if m.Kind == "func_value" {
			fv = true
		}
	}
	if !fv {
		t.Fatalf("expected func_value marker, got %+v", markers)
	}
}

func TestFindEntrypoints(t *testing.T) {
	ix := fixture(t, "constprod")
	eps, err := ix.FindEntrypoints(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 || eps[0].Kind != "main" {
		t.Fatalf("entrypoints=%+v", eps)
	}
}

func TestFindListeners(t *testing.T) {
	ix := fixture(t, "srvprod")
	eps, err := ix.FindListeners(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 1 {
		t.Fatalf("listeners=%+v", eps)
	}
	if eps[0].Kind != "listener" || eps[0].Function != "serve" {
		t.Fatalf("got %+v", eps[0])
	}
}

func TestTraceFieldOrigin(t *testing.T) {
	ix := fixture(t, "fieldprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	// the field-hop chain needs the deep-trace budget (default is 2).
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 6)
	if err != nil {
		t.Fatal(err)
	}
	// r.s <- setS param <- cfg.s <- mapstructure tag (no literal writes).
	if flow.Origin != domain.OriginConfiguration {
		t.Fatalf("origin=%s want CONFIGURATION via field write sites (%s)",
			flow.Origin, flow.Summary)
	}
	if !strings.Contains(flow.Summary, "mapstructure") {
		t.Fatalf("tag-based provenance missing from summary: %s", flow.Summary)
	}
}

func TestFieldWriteGuards(t *testing.T) {
	ix := fixture(t, "fieldprod")
	sites, err := ix.FindCallers(context.Background(), vulnSym)
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	var sanitize, covers bool
	for _, v := range vals {
		if v.Guard && strings.Contains(v.Property, "sanitize-switch") {
			sanitize = true
		}
		if v.Covers != nil && v.Covers.Line == sites[0].Line {
			covers = true
		}
	}
	if !sanitize {
		t.Fatalf("no sanitize-switch guard recorded: %+v", vals)
	}
	if !covers {
		t.Fatalf("field write sites fully bounded but no Covers record: %+v", vals)
	}
}

// The rm6m setPrefetchSize shape: the switch compares `size` while every
// clause assigns a different sanitized var; the field write wraps the
// local in `int(fs.Bytes())`. Covers must still be emitted — the compared
// var is bounded on both sides and the default converts it.
func TestFieldWriteGuardsRangeGated(t *testing.T) {
	ix := fixture(t, "fieldprod")
	sites, err := ix.FindCallers(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Qos"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	var gated, covers bool
	for _, v := range vals {
		if v.Guard && strings.Contains(v.Property, "range-gated") {
			gated = true
		}
		if v.Covers != nil && v.Covers.Line == sites[0].Line {
			covers = true
		}
	}
	if !gated {
		t.Fatalf("no range-gated sanitize-switch guard recorded: %+v", vals)
	}
	if !covers {
		t.Fatalf("range-gated write sites fully bounded but no Covers record: %+v", vals)
	}
	// The range-gated guard must carry its enforced numeric range:
	// size<0 → fs=0, size>1024 → fs=1024, default fs=size → [0,1024].
	var gotLo, gotHi bool
	for _, v := range vals {
		if v.BoundLow != nil && *v.BoundLow == 0 {
			gotLo = true
		}
		if v.BoundHigh != nil && *v.BoundHigh == 1024 {
			gotHi = true
		}
	}
	if !gotLo || !gotHi {
		t.Fatalf("expected bound range [0,1024] on guard records: %+v", vals)
	}
}

// A switch that bounds the compared var on one side only must not be a
// guard for a different var — the default assignment of an unbounded
// half-range is not bounded.
func TestSanitizeSwitchOneSidedNoGuard(t *testing.T) {
	ix := fixture(t, "onesidedprod")
	sites, err := ix.FindCallers(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Qos"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range vals {
		if v.Covers != nil && v.Covers.Line == sites[0].Line {
			t.Fatalf("one-sided switch wrongly covers the sink: %+v", vals)
		}
	}
}

// &r.limit hands out a writable alias — fieldWriteGuards must refuse to
// emit a Covers record even though the only syntactic write is clamped.
func TestFieldWriteGuardsAddressTaken(t *testing.T) {
	ix := fixture(t, "addrtakenprod")
	sites, err := ix.FindCallers(context.Background(),
		domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "Qos"})
	if err != nil || len(sites) != 1 {
		t.Fatalf("sites=%v err=%v", sites, err)
	}
	vals, _, err := ix.FindValidations(context.Background(), sites[0], 0)
	if err != nil {
		t.Fatal(err)
	}
	var noted bool
	for _, v := range vals {
		if v.Covers != nil && v.Covers.Line == sites[0].Line {
			t.Fatalf("address-taken field wrongly covers the sink: %+v", vals)
		}
		if strings.Contains(v.Property, "address taken") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("expected address-taken limitation record: %+v", vals)
	}
}

// reflectprod imports reflect for both a read-only TypeOf call and a
// reflect.Value.SetInt write — the import marker and the write marker are
// distinct kinds.
func TestScanDynamicReflectWrite(t *testing.T) {
	ix := fixture(t, "reflectprod")
	markers, err := ix.ScanDynamic(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	var bare, write, uwrite, uptr bool
	for _, m := range markers {
		switch m.Kind {
		case "reflect":
			bare = true
		case "reflect_write":
			write = true
			if !strings.Contains(m.Detail, "SetInt") {
				t.Fatalf("reflect_write detail=%q", m.Detail)
			}
		case "unsafe_write":
			uwrite = true
		case "unsafe_ptr":
			uptr = true
		}
	}
	if !bare {
		t.Fatal("expected bare reflect import marker")
	}
	if !write {
		t.Fatalf("expected reflect_write marker for Value.SetInt, got %+v", markers)
	}
	if !uwrite {
		t.Fatalf("expected unsafe_write marker for deref store, got %+v", markers)
	}
	if !uptr {
		t.Fatalf("expected unsafe_ptr marker for Pointer conversion, got %+v", markers)
	}
}

// hasExportedCoveredField gates whether a reflect_write marker weakens a
// guard-based FALSE: only an exported covered field is reachable to
// reflect.Value.Set*.
func TestHasExportedCoveredField(t *testing.T) {
	mkCase := func(props ...string) *domain.AnalysisCase {
		c := &domain.AnalysisCase{}
		for _, p := range props {
			c.EvidenceGraph.Validations = append(c.EvidenceGraph.Validations,
				domain.Validation{Property: p})
		}
		return c
	}
	claim := domain.Claim{ConditionID: "C1"}

	if !hasExportedCoveredField(
		mkCase("cond=C1 field-write Mode: sanitize-switch"), claim) {
		t.Fatal("exported covered field must report true")
	}
	if hasExportedCoveredField(
		mkCase("cond=C1 field-write mode: sanitize-switch"), claim) {
		t.Fatal("unexported covered field must report false")
	}
	if hasExportedCoveredField(
		mkCase("cond=C2 field-write Mode: sanitize-switch"), claim) {
		t.Fatal("field covered for a different condition must not count")
	}
	if hasExportedCoveredField(mkCase("cond=C1 count > max → count = max"), claim) {
		t.Fatal("no field-backed guard must report false")
	}
}

// Dep-internal provenance (backlog B3): an unexported subject has no
// product callers — its arguments are fed inside the dependency itself.
// The chain `c.r` <- bufio.NewReader(conn) <- net.Dial must resolve to
// EXTERNAL_UNTRUSTED: the peer boundary is the net.Conn value.
func TestTraceDepInternalPeerOrigin(t *testing.T) {
	ix := fixture(t, "wireprod")
	subj := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "readRecord"}
	sites, err := ix.FindDepCallers(context.Background(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Function != "Next" {
		t.Fatalf("dep callers=%+v", sites)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("origin=%s want EXTERNAL_UNTRUSTED (%s)", flow.Origin, flow.Summary)
	}
}

// Instantiation narrowing: an interface impl that is never created in
// non-test code cannot be a dispatch target — depCone must not contain
// it, and its methods must not inherit the interface's call sites.
func TestInstantiatedNarrowing(t *testing.T) {
	ix := fixture(t, "regprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	cone := ix.depCone("example.com/dep")
	if cone == nil {
		t.Fatal("depCone nil — module load failed")
	}
	if !cone["example.com/dep/vuln.RealRunner.Run"] {
		t.Fatal("RealRunner.Run missing from cone — registered impl dropped")
	}
	if cone["example.com/dep/vuln.NeverRunner.Run"] {
		t.Fatal("NeverRunner.Run in cone — uninstantiated impl dispatched")
	}
	dead := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "NeverRunner.Run"}
	if got := ix.ifaceCallerRefs(dead); len(got) != 0 {
		t.Fatalf("NeverRunner.Run inherited iface callers: %+v", got)
	}
	live := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "RealRunner.Run"}
	if got := ix.ifaceCallerRefs(live); len(got) == 0 {
		t.Fatal("RealRunner.Run lost its iface callers — narrowing over-fired")
	}
}

// Dispatch-key narrowing: an impl registered under a key the product
// never passes cannot be a target of the `runners[name].Run` site —
// even though it is instantiated (the registry literal counts).
func TestDispatchKeyNarrowing(t *testing.T) {
	ix := fixture(t, "regprod")
	if err := ix.load(context.Background()); err != nil {
		t.Fatal(err)
	}
	cone := ix.depCone("example.com/dep")
	if cone == nil {
		t.Fatal("depCone nil — module load failed")
	}
	if !cone["example.com/dep/vuln.RealRunner.Run"] {
		t.Fatal("RealRunner.Run missing — key 'real' must dispatch to it")
	}
	if cone["example.com/dep/vuln.OtherRunner.Run"] {
		t.Fatal("OtherRunner.Run in cone — unreachable key 'other' dispatched")
	}
	off := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "OtherRunner.Run"}
	depPkg := ix.pkgByPath(context.Background(), "example.com/dep/vuln")
	if depPkg == nil {
		t.Fatal("dep pkg not loaded")
	}
	if got := ix.callersOf(depPkg, off); len(got) != 0 {
		t.Fatalf("OtherRunner.Run inherited iface callers past key narrowing: %+v", got)
	}
}

// The dep-internal caller may live in a sibling package of the same
// module — a package-scoped scan would miss it and keep a false VERIFIED.
func TestDepCallerSiblingPackage(t *testing.T) {
	ix := fixture(t, "xmodprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep5"

	subj := domain.SymbolRef{Package: "example.com/dep5/deep", Symbol: "Sink"}
	callers, _, unbounded, err := ix.DepInvocationState(context.Background(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if callers == 0 {
		t.Fatal("dep caller in sibling package dep5/driver not found — scan stayed package-scoped")
	}
	if unbounded {
		t.Fatal("dep5/deep is imported only inside its own module — caller set is bounded")
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-REACH", Result: domain.ClaimFalse}
	out := v.verifyReachableFalse(context.Background(), c, claim, nv,
		[]domain.SymbolRef{subj}, map[string][]domain.CallSite{})
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v — sibling-package dep caller must demote the falsifier", got)
	}
}

// With a multi-module advisory whose entries are BOTH linked, the dep
// invocation gate must cover subjects of every selected module — a
// second module's live dep caller is not excused by Vulnerability.Module
// naming only the first.
func TestDepCallerMultiModuleUnion(t *testing.T) {
	ix := fixture(t, "xmodprod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep" // first module — not the
	// one owning the subject
	c.Affected = &domain.AffectedResult{
		SelectedModules: []string{"example.com/dep", "example.com/dep5"},
	}
	subj := domain.SymbolRef{Package: "example.com/dep5/deep", Symbol: "Sink"}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-REACH", Result: domain.ClaimFalse}
	out := v.verifyReachableFalse(context.Background(), c, claim, nv,
		[]domain.SymbolRef{subj}, map[string][]domain.CallSite{})
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeInsufficientScope {
		t.Fatalf("nv=%+v — second-module subject's dep caller must demote the falsifier", got)
	}
}

// Same dep scope, opposite origin: a subject only invoked with constants
// inside the dep resolves a non-external origin — traced evidence that
// contradicts the unexported+peer heuristic.
func TestTraceDepInternalConstantOrigin(t *testing.T) {
	ix := fixture(t, "wireprod")
	subj := domain.SymbolRef{Package: "example.com/dep/vuln", Symbol: "parseConstant"}
	sites, err := ix.FindDepCallers(context.Background(), subj)
	if err != nil {
		t.Fatal(err)
	}
	if len(sites) != 1 || sites[0].Function != "Fixed" {
		t.Fatalf("dep callers=%+v", sites)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginConstant {
		t.Fatalf("origin=%s want CONSTANT (%s)", flow.Origin, flow.Summary)
	}
}

// Input-verification FALSE must trace dep-internal callers for subjects
// of EVERY selected module: subject one has only a safe product call,
// subject two lives in the second module and is invoked solely inside
// the dependency with external input — a single-module membership check
// would skip it and keep VERIFIED-FALSE.
func TestVerifyInputFalseSecondModule(t *testing.T) {
	ix := fixture(t, "duomod")
	v := Verifier{Source: ix}
	c := &domain.AnalysisCase{}
	c.Vulnerability.Module = "example.com/dep"
	c.Affected = &domain.AffectedResult{
		SelectedModules: []string{"example.com/dep", "example.com/dep5"},
	}
	subjects := []domain.SymbolRef{
		{Package: "example.com/dep/vuln", Symbol: "Parse"},
		{Package: "example.com/dep5/deep", Symbol: "Sink"},
	}
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	claim := domain.Claim{ConditionID: "C-INPUT", Result: domain.ClaimFalse}
	out := v.verifyInputFalse(context.Background(), c, claim, nv, subjects, 0)
	got := out.NegativeVerification
	if got == nil || got.Status != domain.NegativeContradicted {
		t.Fatalf("nv=%+v — external input through a second-module dep caller must contradict FALSE", got)
	}
}

func TestInputOriginVerificationUnknownValue(t *testing.T) {
	for _, origin := range []domain.DataOrigin{"", domain.OriginUnknown, "FUTURE_ORIGIN"} {
		if got := inputOriginVerification(origin); got != domain.NegativeInsufficientScope {
			t.Errorf("origin %q: status = %s, want INSUFFICIENT_SCOPE", origin, got)
		}
	}
	for _, origin := range []domain.DataOrigin{domain.OriginConstant, domain.OriginGenerated} {
		if got := inputOriginVerification(origin); got != domain.NegativeVerified {
			t.Errorf("origin %q: status = %s, want VERIFIED", origin, got)
		}
	}
}
