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

// reflectprod imports reflect for both a read-only TypeOf call and a
// reflect.Value.SetInt write — the import marker and the write marker are
// distinct kinds.
func TestScanDynamicReflectWrite(t *testing.T) {
	ix := fixture(t, "reflectprod")
	markers, err := ix.ScanDynamic(context.Background(), vulnSym)
	if err != nil {
		t.Fatal(err)
	}
	var bare, write bool
	for _, m := range markers {
		switch m.Kind {
		case "reflect":
			bare = true
		case "reflect_write":
			write = true
			if !strings.Contains(m.Detail, "SetInt") {
				t.Fatalf("reflect_write detail=%q", m.Detail)
			}
		}
	}
	if !bare {
		t.Fatal("expected bare reflect import marker")
	}
	if !write {
		t.Fatalf("expected reflect_write marker for Value.SetInt, got %+v", markers)
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
