package goanalysis

import (
	"context"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func TestTraceCalleeLocalPopulatedAfterInitialization(t *testing.T) {
	ix := fixture(t, "calleemutprod")
	subj := domain.SymbolRef{Package: "example.com/calleemutdep", Symbol: "Sink"}
	sites, err := ix.FindDepCallers(context.Background(), subj)
	if err != nil || len(sites) != 1 {
		t.Fatalf("dep callers=%+v err=%v", sites, err)
	}
	flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 16)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Origin != domain.OriginExternalUntrusted {
		t.Fatalf("origin=%s want EXTERNAL_UNTRUSTED (%s)", flow.Origin, flow.Summary)
	}
}

func TestTraceCalleeReceiverMutationAndOutParameterAfterInitialization(t *testing.T) {
	for _, subject := range []domain.SymbolRef{
		{Package: "example.com/calleemutdep", Symbol: "SinkBuffer"},
		{Package: "example.com/calleemutdep", Symbol: "SinkLength"},
	} {
		t.Run(subject.Symbol, func(t *testing.T) {
			ix := fixture(t, "calleemutprod")
			sites, err := ix.FindDepCallers(context.Background(), subject)
			if err != nil || len(sites) != 1 {
				t.Fatalf("dep callers=%+v err=%v", sites, err)
			}
			flow, _, err := ix.TraceArgumentBound(context.Background(), sites[0], 0, 16)
			if err != nil {
				t.Fatal(err)
			}
			if flow.Origin != domain.OriginExternalUntrusted {
				t.Fatalf("origin=%s want EXTERNAL_UNTRUSTED (%s)", flow.Origin, flow.Summary)
			}
		})
	}
}

func TestTraceDirectProductLocalsMergeCallsAndInitializers(t *testing.T) {
	ix := fixture(t, "calleemutdirectprod")
	subject := domain.SymbolRef{Package: "example.com/calleemutdep", Symbol: "SinkBuffer"}
	sites, err := ix.FindCallers(context.Background(), subject)
	if err != nil {
		t.Fatal(err)
	}
	for _, site := range sites {
		if site.Package != "example.com/calleemutdirectprod" {
			continue
		}
		flow, _, err := ix.TraceArgumentBound(context.Background(), site, 0, 16)
		if err != nil {
			t.Fatal(err)
		}
		if flow.Origin != domain.OriginExternalUntrusted {
			t.Fatalf("origin=%s want EXTERNAL_UNTRUSTED (%s)", flow.Origin, flow.Summary)
		}
		return
	}
	t.Fatalf("product caller not found for %s: %+v", subject, sites)
}
