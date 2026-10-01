package justification

import (
	"fmt"
	"strings"

	"example.com/vuln-analyzer/internal/domain"
)

// Build constructs an audit-ready AnalysisJustification based strictly on verified facts
// and proposals, preserving honest uncertainty (human remainder).
func Build(c *domain.AnalysisCase) domain.AnalysisJustification {
	verdict := domain.VerdictInconclusive
	if c.Verdict != nil {
		verdict = c.Verdict.Verdict
	}

	d := domain.AnalysisJustification{
		VulnerabilityID: c.Vulnerability.ID,
		Verdict:         verdict,
	}

	if c.CVEAnalysis != nil && len(c.CVEAnalysis.Mechanisms) > 0 {
		m := c.CVEAnalysis.Mechanisms[0]
		d.TechnicalMechanism = m.Summary
		if len(m.FaultingSites) > 0 {
			d.TechnicalMechanism = fmt.Sprintf("%s (сайты дефекта: %s)", m.Summary, strings.Join(m.FaultingSites, ", "))
			for _, fs := range m.FaultingSites {
				d.VerifiedFacts = append(d.VerifiedFacts, fmt.Sprintf("Сайт дефекта: %s", fs))
			}
		}

		// If case is EXPLOITABLE or INCONCLUSIVE and auxiliary symbols exist without human decision,
		// record them in HumanRemainder rather than altering verdict.
		if verdict == domain.VerdictExploitable || verdict == domain.VerdictInconclusive {
			for _, aux := range m.AuxiliarySites {
				d.HumanRemainder = append(d.HumanRemainder, domain.HumanRemainderItem{
					Obligation: "verify_auxiliary_symbol",
					Question:   fmt.Sprintf("Подтвердить, что функция %s является вспомогательным транспортом/проверкой и не содержит сайта сбоя", aux),
				})
			}
		}
	}

	return d
}
