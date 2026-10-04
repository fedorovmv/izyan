package evaluator

import (
	"strings"
	"testing"

	"github.com/fedorovmv/izyan/internal/domain"
)

func exposureCond() domain.Condition {
	return domain.Condition{
		ID:        "C-EXPOSURE",
		Kind:      domain.ConditionConfiguration,
		Params:    map[string]string{domain.ParamCheck: domain.CheckExposure},
		Mandatory: false,
	}
}

func exposureCase(facts ...domain.ExposureFact) *domain.AnalysisCase {
	c := &domain.AnalysisCase{}
	for _, f := range facts {
		c.EvidenceGraph.AddExposure(f)
	}
	c.EvidenceGraph.AddEvidence(domain.Evidence{
		Kind:    domain.EvidenceConfiguration,
		Quality: domain.QualityDeterministic,
		Source:  "source index + repo config scan: exposure",
		Tool:    "goanalysis.Index.ListenSites+DialSites, exposure.ScanRepo",
		Content: "facts",
	})
	return c
}

func TestExposureResolved(t *testing.T) {
	c := exposureCase(
		domain.ExposureFact{Direction: "inbound", Kind: "listener", Target: "net.Listen",
			Address: ":9090", AddressSource: "literal", Scope: domain.ScopeAllInterfaces},
		domain.ExposureFact{Direction: "outbound", Kind: "dial", Target: "dep/vuln.Dial",
			AddressSource: "env:AMQP_URL", Scope: domain.ScopeConfigured},
	)
	cl := Exposure{}.Evaluate(exposureCond(), c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("result=%s (%s)", cl.Result, cl.Explanation)
	}
	if len(cl.EvidenceIDs) == 0 {
		t.Fatal("TRUE claim must carry evidence")
	}
	if !strings.Contains(cl.Explanation, "net.Listen=:9090") ||
		!strings.Contains(cl.Explanation, "dep/vuln.Dial") {
		t.Fatalf("explanation=%s", cl.Explanation)
	}
	found := false
	for _, l := range cl.Limitations {
		if strings.Contains(l, "operator-configured") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected configured-endpoint caveat, got %v", cl.Limitations)
	}
}

func TestExposureLoopbackCaveat(t *testing.T) {
	c := exposureCase(domain.ExposureFact{Direction: "inbound", Kind: "listener",
		Target: "net.Listen", Address: "127.0.0.1:8080", AddressSource: "literal", Scope: domain.ScopeLoopback})
	cl := Exposure{}.Evaluate(exposureCond(), c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("result=%s", cl.Result)
	}
	found := false
	for _, l := range cl.Limitations {
		if strings.Contains(l, "loopback") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected loopback caveat, got %v", cl.Limitations)
	}
}

func TestExposureNoFacts(t *testing.T) {
	cl := Exposure{}.Evaluate(exposureCond(), exposureCase())
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s, want UNKNOWN", cl.Result)
	}
	// no scan evidence at all → different limitation path
	cl = Exposure{}.Evaluate(exposureCond(), &domain.AnalysisCase{})
	if cl.Result != domain.ClaimUnknown ||
		!strings.Contains(cl.Limitations[0], "did not run") {
		t.Fatalf("result=%s lims=%v", cl.Result, cl.Limitations)
	}
}

func TestExposure_PublicScopeFalsified(t *testing.T) {
	c := exposureCase(
		domain.ExposureFact{Direction: "inbound", Kind: "listener",
			Target: "net.Listen", Address: "127.0.0.1:8080", AddressSource: "literal", Scope: domain.ScopeLoopback},
		domain.ExposureFact{Direction: "inbound", Kind: "deployment",
			Target: "k8s:Service:ClusterIP", Address: "ClusterIP", AddressSource: "manifest", Scope: domain.ScopeLoopback},
	)
	cond := exposureCond()
	cond.Params[domain.ParamScope] = "public"
	cl := Exposure{}.Evaluate(cond, c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("result=%s, want FALSE", cl.Result)
	}
	if cl.Falsifier != domain.FalsifierLoopbackOnly {
		t.Fatalf("falsifier=%s, want %s", cl.Falsifier, domain.FalsifierLoopbackOnly)
	}
}

func TestExposure_PublicScopeSatisfied(t *testing.T) {
	c := exposureCase(
		domain.ExposureFact{Direction: "inbound", Kind: "listener",
			Target: "net.Listen", Address: "127.0.0.1:8080", AddressSource: "literal", Scope: domain.ScopeLoopback},
		domain.ExposureFact{Direction: "inbound", Kind: "deployment",
			Target: "gateway-api:Gateway", Address: "api.example.com", AddressSource: "manifest", Scope: domain.ScopeAllInterfaces},
	)
	cond := exposureCond()
	cond.Params[domain.ParamScope] = "public"
	cl := Exposure{}.Evaluate(cond, c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("result=%s, want TRUE", cl.Result)
	}
}
