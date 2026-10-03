package goanalysis

import (
	"context"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
	"golang.org/x/tools/go/packages"
)

func TestClosureReleasesPinnedModule(t *testing.T) {
	for _, sink := range []bool{false, true} {
		t.Run(map[bool]string{false: "ingress", true: "sink"}[sink], func(t *testing.T) {
			ix := fixture(t, "constprod")
			var err error
			if sink {
				_, _, err = ix.SinkClosure(context.Background(), "C", "example.com/dep", "probe", []domain.SymbolRef{vulnSym}, 0, 16)
			} else {
				_, _, err = ix.IngressInventory(context.Background(), "example.com/dep", []domain.SymbolRef{vulnSym}, 16)
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(ix.extraPinned) != 0 {
				t.Fatalf("finished query retained pinned modules: %v", ix.extraPinned)
			}
		})
	}
}

func TestExtraEvictionRetainsNewestLoadWhenOlderPinned(t *testing.T) {
	ix := &Index{
		extraPkgs: map[string][]*packages.Package{
			"old": make([]*packages.Package, maxExtraPkgs),
			"new": {{PkgPath: "new"}},
		},
		extraOrder:  []string{"old", "new"},
		extraPinned: map[string]bool{"old": true},
	}
	for i := range ix.extraPkgs["old"] {
		ix.extraPkgs["old"][i] = &packages.Package{PkgPath: "old"}
	}
	ix.evictExtra()
	if _, ok := ix.extraPkgs["new"]; !ok {
		t.Fatal("evicted the active newest load while older module was pinned")
	}
}

func TestIngressVerificationPersistsCurrentCoverage(t *testing.T) {
	ix := fixture(t, "constprod")
	c := &domain.AnalysisCase{Vulnerability: domain.Vulnerability{Module: "example.com/dep"}}
	c.EvidenceGraph.AddIngressClosure(domain.IngressClosure{
		ConditionID: "C", Module: "example.com/dep", Blockers: []string{"stale inventory"},
	})
	nv := &domain.NegativeVerification{Status: domain.NegativeVerified}
	(Verifier{Source: ix}).verifyIngress(context.Background(), c, "C", nv, []domain.SymbolRef{vulnSym})
	cl := c.EvidenceGraph.IngressClosureFor("C")
	if cl == nil || len(cl.Items) == 0 {
		t.Fatalf("verification did not persist the current inventory: %+v", cl)
	}
	for _, b := range cl.Blockers {
		if b == "stale inventory" {
			t.Fatal("report retained obsolete coverage after verification")
		}
	}
}

func TestGuardVerificationRejectsUnresolvedInput(t *testing.T) {
	for _, origin := range []domain.DataOrigin{domain.OriginUnknown, ""} {
		c := &domain.AnalysisCase{}
		site := domain.CallSite{File: "dep.go", Line: 8, Package: "example.com/dep/vuln"}
		c.EvidenceGraph.DataFlows = []domain.DataFlow{{ConditionID: "C", Sink: site, Arg: 0, Origin: origin}}
		c.EvidenceGraph.Validations = []domain.Validation{{Guard: true, Covers: &site, Arg: 0}}
		claim := (Verifier{}).verifyGuardFalse(context.Background(), c,
			domain.Claim{ConditionID: "C", Result: domain.ClaimFalse, Falsifier: domain.FalsifierGuards},
			&domain.NegativeVerification{Status: domain.NegativeVerified})
		if claim.NegativeVerification.Status != domain.NegativeInsufficientScope {
			t.Fatalf("unresolved guarded input verified: %+v", claim)
		}
	}
}
