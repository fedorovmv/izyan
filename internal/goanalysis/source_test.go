package goanalysis

import (
	"context"
	"path/filepath"
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
