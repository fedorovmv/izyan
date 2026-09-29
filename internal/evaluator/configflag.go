package evaluator

import (
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// ConfigFlag evaluates check=config_flag / check=config_key conditions —
// the effective value of a configuration knob the advisory cares about
// (TLS verification, debug mode, auth toggles).
//
//	config_flag — assignments to a pkg.Type.Field knob collected into
//	  EvidenceGraph.ConfigFlags; a literal/const value equal to
//	  insecure_value → TRUE, only safe assignments → FALSE candidate,
//	  unresolved or absent values → UNKNOWN (never-set bool knobs apply
//	  the Go zero-value rule when insecure_value is non-zero).
//	config_key — EvidenceGraph.Configuration items matched on the key;
//	  a hit with the insecure value → TRUE, safe values → FALSE
//	  candidate, no items → UNKNOWN (env/deployment can set it outside
//	  the repo).
//
// FALSE candidates have no dedicated falsification strategy — the
// negative-check pass marks them INSUFFICIENT_SCOPE rather than
// verified, which is honest: "knob set safely in the files we saw" is a
// weak negative.
type ConfigFlag struct{}

func (ConfigFlag) CanEvaluate(cond domain.Condition) bool {
	ch := cond.Params[domain.ParamCheck]
	return ch == domain.CheckConfigFlag || ch == domain.CheckConfigKey
}

func (ConfigFlag) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	claim := domain.Claim{
		ID:          domain.ClaimID("CL-" + string(cond.ID)),
		ConditionID: cond.ID,
		Result:      domain.ClaimUnknown,
		Producer:    "evaluator.ConfigFlag",
	}
	insecure := cond.Params[domain.ParamInsecure]
	if insecure == "" {
		insecure = "true"
	}
	switch cond.Params[domain.ParamCheck] {
	case domain.CheckConfigFlag:
		return evalConfigFlag(cond, c, claim, insecure)
	case domain.CheckConfigKey:
		return evalConfigKey(cond, c, claim, insecure)
	}
	return claim
}

func evalConfigFlag(cond domain.Condition, c *domain.AnalysisCase, claim domain.Claim, insecure string) domain.Claim {
	pkg, sym := cond.Params[domain.ParamConfigPackage], cond.Params[domain.ParamConfigSymbol]
	if pkg == "" || sym == "" {
		claim.Limitations = append(claim.Limitations, "no config_package/config_symbol param — knob unspecified")
		return claim
	}
	key := pkg + "." + sym
	claim.EvidenceIDs = exposureEvidenceIDs(c, "config flag check ")
	if _, ok := c.EvidenceGraph.SymbolDeclFor(key); !ok {
		claim.Limitations = append(claim.Limitations, "knob existence not verified in source")
	}
	list, checked := c.EvidenceGraph.ConfigFlagsFor(key)
	if !checked {
		claim.Limitations = append(claim.Limitations, "assignment scan did not run")
		return claim
	}
	var insecureSites, safeSites, unresolved []domain.ConfigAssignment
	for _, a := range list {
		switch {
		case a.Source == "":
			unresolved = append(unresolved, a)
		case valueEqual(a.Value, insecure):
			insecureSites = append(insecureSites, a)
		default:
			safeSites = append(safeSites, a)
		}
	}
	if len(insecureSites) > 0 {
		claim.Result = domain.ClaimTrue
		var at []string
		for _, s := range insecureSites {
			at = append(at, fmt.Sprintf("%s:%d", s.File, s.Line))
		}
		claim.Explanation = fmt.Sprintf("knob %s set to insecure value %q at %s", sym, insecure, strings.Join(at, ", "))
		return claim
	}
	if len(unresolved) > 0 {
		claim.Limitations = append(claim.Limitations, fmt.Sprintf(
			"%d assignment(s) to %s use non-literal values — effective value unresolved", len(unresolved), sym))
		return claim
	}
	if len(safeSites) > 0 {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = "safe-config-assignment"
		claim.Explanation = fmt.Sprintf("knob %s assigned only safe value(s) at %d site(s)", sym, len(safeSites))
		return claim
	}
	// Never assigned: Go zero-value semantics apply only when we know the
	// field kind (recorded by the collector in the zero_value param echo)
	// — a bool knob never set is false; if that is not the insecure
	// value the configuration is safe by default.
	if zero, ok := c.EvidenceGraph.SymbolFieldKind(key); ok && zero == "bool" &&
		(insecure == "true" || insecure == "1") {
		claim.Result = domain.ClaimFalse
		claim.Falsifier = "zero-value-config"
		claim.Explanation = fmt.Sprintf("knob %s never assigned in product code — Go zero value false is not %q", sym, insecure)
		claim.Limitations = append(claim.Limitations,
			"zero-value reasoning assumes no runtime default override (struct defaults, env layering)")
		return claim
	}
	claim.Limitations = append(claim.Limitations,
		fmt.Sprintf("knob %s never assigned in product code; runtime/deployment value unknown", sym))
	return claim
}

func evalConfigKey(cond domain.Condition, c *domain.AnalysisCase, claim domain.Claim, insecure string) domain.Claim {
	key := cond.Params[domain.ParamConfigKey]
	if key == "" {
		claim.Limitations = append(claim.Limitations, "no config_key param — key unspecified")
		return claim
	}
	claim.EvidenceIDs = exposureEvidenceIDs(c, "config key check ")
	var hits, safe []domain.ConfigItem
	matched := false
	for _, it := range c.EvidenceGraph.ConfigItems() {
		if it.Key == "" || !keyMatches(it.Key, key) {
			continue
		}
		matched = true
		if valueEqual(it.Value, insecure) {
			hits = append(hits, it)
		} else {
			safe = append(safe, it)
		}
	}
	if !matched {
		claim.Limitations = append(claim.Limitations,
			fmt.Sprintf("key %q not found in repo config files; may be set via env/deployment outside the repo", key))
		return claim
	}
	if len(hits) > 0 {
		claim.Result = domain.ClaimTrue
		claim.Explanation = fmt.Sprintf("config key %q set to insecure value %q at %s:%d",
			key, insecure, hits[0].File, hits[0].Line)
		return claim
	}
	claim.Result = domain.ClaimFalse
	claim.Falsifier = "safe-config-key"
	claim.Explanation = fmt.Sprintf("config key %q present with safe value(s)", key)
	return claim
}

// keyMatches mirrors exposure.Lookup semantics: exact key or last dotted
// segment, case-insensitive.
func keyMatches(itemKey, want string) bool {
	k := strings.ToLower(itemKey)
	want = strings.ToLower(want)
	if k == want {
		return true
	}
	if j := strings.LastIndexByte(k, '.'); j >= 0 {
		return k[j+1:] == want
	}
	return false
}

func valueEqual(got, want string) bool {
	return strings.EqualFold(strings.Trim(strings.TrimSpace(got), `"'`), strings.TrimSpace(want))
}

func exposureEvidenceIDs(c *domain.AnalysisCase, prefix string) []domain.EvidenceID {
	var ids []domain.EvidenceID
	for _, e := range c.EvidenceGraph.EvidenceList() {
		if strings.HasPrefix(e.Source, "config flag check ") || strings.HasPrefix(e.Source, "config key check ") {
			ids = appendUniqueID(ids, e.ID)
		}
	}
	return ids
}
