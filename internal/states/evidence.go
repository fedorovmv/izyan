package states

import (
	"context"
	"fmt"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// actCollectEvidence checks if any mandatory condition has ConditionMissingCall.
// When present, it verifies omission via CheckMissingCall and records EV-MISSING-CALL.
func (h CollectEvidence) actCollectEvidence(ctx context.Context, c *domain.AnalysisCase) {
	if h.Source == nil || c == nil || c.Exploit == nil {
		return
	}

	for _, cond := range c.Exploit.MandatoryConditions {
		if cond.Kind != domain.ConditionMissingCall && cond.Params[domain.ParamCheck] != domain.CheckMissingCall {
			continue
		}
		if len(cond.Subjects) == 0 {
			continue
		}

		checkRef := cond.Subjects[0]
		pipelineSym := cond.Params["pipeline"]
		pipelineRef := domain.SymbolRef{Package: checkRef.Package, Symbol: pipelineSym}

		for _, mc := range c.Exploit.MandatoryConditions {
			if (mc.ID == "C-REACH" || mc.Kind == domain.ConditionSymbolReachable) && len(mc.Subjects) > 0 {
				for _, s := range mc.Subjects {
					if s.Symbol == pipelineSym || pipelineSym == "" {
						pipelineRef = s
						break
					}
				}
			}
		}

		omitted, content, callers, err := h.Source.CheckMissingCall(ctx, checkRef, pipelineRef)
		if err != nil {
			c.EvidenceGraph.AddToolLimitation(fmt.Sprintf("missing-call check failed: %v", err))
			continue
		}

		if omitted {
			c.EvidenceGraph.AddEvidence(domain.Evidence{
				ID:      "EV-MISSING-CALL",
				Kind:    domain.EvidenceValidation,
				Quality: domain.QualityDeterministic,
				Source:  "source index: missing-call verification",
				Tool:    "goanalysis.Index.CheckMissingCall",
				Content: content,
			})
			for _, mc := range c.Exploit.MandatoryConditions {
				if mc.ID == "C-INPUT" || mc.Kind == domain.ConditionAttackerControl || mc.Kind == domain.ConditionInputConstraint {
					for _, site := range callers {
						flows, evs, terr := h.traceArgs(ctx, site, mc)
						if terr != nil {
							continue
						}
						for _, flow := range flows {
							flow.ConditionID = mc.ID
							c.EvidenceGraph.AddDataFlows(flow)
						}
						for _, e := range evs {
							c.EvidenceGraph.AddEvidence(e)
						}
					}
				}
			}
		} else if content != "" && strings.Contains(content, "is invoked") {
			c.EvidenceGraph.AddEvidence(domain.Evidence{
				ID:      "EV-CHECK-PRESENT",
				Kind:    domain.EvidenceValidation,
				Quality: domain.QualityDeterministic,
				Source:  "source index: check-call verification",
				Tool:    "goanalysis.Index.CheckMissingCall",
				Content: content,
			})
		}
	}
}
