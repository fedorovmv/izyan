package evaluator

import (
	"github.com/fedorovmv/izyan/internal/domain"
)

// Custom gives CUSTOM conditions a deterministic partial evaluation.
// CUSTOM conditions carrying a check= param are already evaluated
// kind-agnostically (symbol_present, exposure, config_flag, config_key);
// this evaluator handles the remaining shapes by routing onto the
// reachability machinery when the condition declares it:
//
//	check=reachable, or direction=read/sequence params on a CUSTOM
//	condition with subjects — evaluated as a SYMBOL_REACHABLE claim.
//
// A CUSTOM condition without recognizable params stays UNKNOWN with a
// limitation naming the supported routes — it is never guessed.
type Custom struct{}

func (Custom) CanEvaluate(cond domain.Condition) bool {
	return cond.Kind == domain.ConditionCustom
}

func (Custom) Evaluate(cond domain.Condition, c *domain.AnalysisCase) domain.Claim {
	routable := cond.Params[domain.ParamCheck] == domain.CheckReachable ||
		cond.Params[domain.ParamDirection] == domain.DirectionRead ||
		(cond.Params[domain.ParamSequence] != "" && len(cond.Subjects) > 0)
	if !routable {
		return domain.Claim{
			ID:          domain.ClaimID("CL-" + string(cond.ID)),
			ConditionID: cond.ID,
			Result:      domain.ClaimUnknown,
			Producer:    "evaluator.Custom",
			Limitations: []string{
				"custom condition has no deterministic route; supported: " +
					"check=reachable, direction=read, sequence=a->b with subjects " +
					"(check=symbol_present/exposure/config_flag/config_key are " +
					"claimed by their own evaluators)",
			},
		}
	}
	shadow := cond
	shadow.Kind = domain.ConditionSymbolReachable
	cl := SymbolReachable{}.Evaluate(shadow, c)
	cl.Producer = "evaluator.Custom"
	cl.Explanation = "custom condition via reachability: " + cl.Explanation
	return cl
}
