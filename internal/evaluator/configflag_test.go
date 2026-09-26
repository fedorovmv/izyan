package evaluator

import (
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

func tlsCond() domain.Condition {
	return domain.Condition{
		ID:   "C-TLS-VERIFY",
		Kind: domain.ConditionConfiguration,
		Params: map[string]string{
			domain.ParamCheck:         domain.CheckConfigFlag,
			domain.ParamConfigPackage: "crypto/tls",
			domain.ParamConfigSymbol:  "Config.InsecureSkipVerify",
			domain.ParamInsecure:      "true",
		},
	}
}

func TestConfigFlagInsecureAssignment(t *testing.T) {
	c := &domain.AnalysisCase{}
	key := "crypto/tls.Config.InsecureSkipVerify"
	c.EvidenceGraph.AddConfigFlag(key, domain.ConfigAssignment{
		Subject: key, Value: "true", Source: "literal",
		CallSite: domain.CallSite{File: "x.go", Line: 3},
	})
	cl := ConfigFlag{}.Evaluate(tlsCond(), c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("result=%s lim=%v", cl.Result, cl.Limitations)
	}
}

func TestConfigFlagSafeAssignmentFalse(t *testing.T) {
	c := &domain.AnalysisCase{}
	key := "crypto/tls.Config.InsecureSkipVerify"
	c.EvidenceGraph.AddConfigFlag(key, domain.ConfigAssignment{
		Subject: key, Value: "false", Source: "literal",
		CallSite: domain.CallSite{File: "x.go", Line: 3},
	})
	cl := ConfigFlag{}.Evaluate(tlsCond(), c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("result=%s", cl.Result)
	}
}

func TestConfigFlagNeverSetBoolZeroValue(t *testing.T) {
	c := &domain.AnalysisCase{}
	key := "crypto/tls.Config.InsecureSkipVerify"
	c.EvidenceGraph.AddConfigFlag(key) // checked, none found
	c.EvidenceGraph.AddConfigFieldKind(key, "bool")
	cl := ConfigFlag{}.Evaluate(tlsCond(), c)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("result=%s lim=%v", cl.Result, cl.Limitations)
	}
}

func TestConfigFlagNeverSetUnknownKind(t *testing.T) {
	c := &domain.AnalysisCase{}
	key := "crypto/tls.Config.InsecureSkipVerify"
	c.EvidenceGraph.AddConfigFlag(key)
	cl := ConfigFlag{}.Evaluate(tlsCond(), c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s", cl.Result)
	}
}

func TestConfigFlagNonLiteral(t *testing.T) {
	c := &domain.AnalysisCase{}
	key := "crypto/tls.Config.InsecureSkipVerify"
	c.EvidenceGraph.AddConfigFlag(key, domain.ConfigAssignment{
		Subject: key, CallSite: domain.CallSite{File: "x.go", Line: 3},
	})
	cl := ConfigFlag{}.Evaluate(tlsCond(), c)
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("result=%s", cl.Result)
	}
}

func TestConfigKeyEvaluation(t *testing.T) {
	cond := domain.Condition{
		ID:   "C-DBG",
		Kind: domain.ConditionConfiguration,
		Params: map[string]string{
			domain.ParamCheck:     domain.CheckConfigKey,
			domain.ParamConfigKey: "debug",
			domain.ParamInsecure:  "true",
		},
	}
	c := &domain.AnalysisCase{}
	c.EvidenceGraph.AddConfigItem(domain.ConfigItem{Key: "server.debug", Value: "true", File: "app.yaml", Line: 4})
	cl := ConfigFlag{}.Evaluate(cond, c)
	if cl.Result != domain.ClaimTrue {
		t.Fatalf("result=%s", cl.Result)
	}

	c2 := &domain.AnalysisCase{}
	c2.EvidenceGraph.AddConfigItem(domain.ConfigItem{Key: "server.debug", Value: "false"})
	cl = ConfigFlag{}.Evaluate(cond, c2)
	if cl.Result != domain.ClaimFalse {
		t.Fatalf("safe value: result=%s", cl.Result)
	}

	cl = ConfigFlag{}.Evaluate(cond, &domain.AnalysisCase{})
	if cl.Result != domain.ClaimUnknown {
		t.Fatalf("no items: result=%s", cl.Result)
	}
}
