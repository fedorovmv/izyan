package risk

import (
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
)

// Assess evaluates the contextual risk and assigns a triage priority tier
// based on nominal severity and concrete product execution context.
func Assess(v domain.Vulnerability, c *domain.AnalysisCase, vr domain.VerdictResult) domain.ContextualRisk {
	baseSev := strings.ToUpper(strings.TrimSpace(v.BaseSeverity))
	baseScore := v.BaseScore
	if baseScore <= 0 {
		baseScore = defaultScoreForSeverity(baseSev)
	}
	if baseSev == "" {
		baseSev = defaultSeverityForScore(baseScore)
	}

	exposure := detectExposure(c)
	authn := detectAuthentication(c)

	factors := domain.RiskFactors{
		Verdict:        string(vr.Verdict),
		Exposure:       exposure,
		Authentication: authn,
		PayloadControl: "UNKNOWN",
		BlastRadius:    "UNKNOWN",
	}

	// Rule 1: Dismissed (NOT_AFFECTED or NO_EXPLOIT_PATH_FOUND)
	if vr.Verdict == domain.VerdictNotAffected {
		return domain.ContextualRisk{
			Status:           domain.RiskStatusNotApplicable,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  domain.RiskLevelNone,
			ContextualScore:  0.0,
			Priority:         domain.PriorityDismissed,
			SLA:              "None (No remediation required)",
			AdjustmentReason: "Уязвимый модуль не слинкован в бинарный граф сборки продукта (go list -deps). Эксплуатация физически невозможна. Блокировка сборки снята.",
			Factors:          factors,
		}
	}

	if vr.Verdict == domain.VerdictNoExploitPathFound {
		return domain.ContextualRisk{
			Status:           domain.RiskStatusAssessed,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  domain.RiskLevelNone,
			ContextualScore:  0.0,
			Priority:         domain.PriorityDismissed,
			SLA:              "None (No remediation required)",
			AdjustmentReason: "Обязательное условие эксплуатации опровергнуто детерминированной верификацией. Уязвимый путь вызова отсутствует. Блокировка сборки снята.",
			Factors:          factors,
		}
	}

	// Rule 5: Inconclusive / Provisional
	if vr.Verdict == domain.VerdictInconclusive {
		prio := domain.PriorityP2
		lvl := domain.RiskLevelMedium
		sla := "Sprint (30 days)"
		if baseScore >= 9.0 || baseSev == "CRITICAL" || baseSev == "BLOCKER" {
			prio = domain.PriorityP1
			lvl = domain.RiskLevelHigh
			sla = "7 days (Manual triage required)"
		}
		return domain.ContextualRisk{
			Status:           domain.RiskStatusProvisional,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  lvl,
			ContextualScore:  baseScore,
			Priority:         prio,
			SLA:              sla,
			AdjustmentReason: "Условия эксплуатации не подтверждены и не опровергнуты; требуется ручной триаж входных данных и конфигурации.",
			Factors:          factors,
		}
	}

	// If verdict is EXPLOITABLE
	if vr.Verdict == domain.VerdictExploitable {
		// Rule 2: Blocker P0 (PUBLIC exposure without required authentication)
		if exposure == "PUBLIC" && authn != "REQUIRED" {
			score := baseScore
			if score < 9.5 {
				score = 10.0
			}
			return domain.ContextualRisk{
				Status:           domain.RiskStatusAssessed,
				BaseSeverity:     baseSev,
				BaseScore:        baseScore,
				ContextualLevel:  domain.RiskLevelCritical,
				ContextualScore:  score,
				Priority:         domain.PriorityP0,
				SLA:              "24h (Immediate remediation required)",
				AdjustmentReason: "Критическая уязвимость подтверждена: сервис слушает внешний сетевой интерфейс (0.0.0.0) без обязательной аутентификации.",
				Factors:          factors,
			}
		}

		// Rule 3: P1 Critical/High (PUBLIC exposure with authentication REQUIRED)
		if exposure == "PUBLIC" && authn == "REQUIRED" {
			return domain.ContextualRisk{
				Status:           domain.RiskStatusAssessed,
				BaseSeverity:     baseSev,
				BaseScore:        baseScore,
				ContextualLevel:  domain.RiskLevelHigh,
				ContextualScore:  7.5,
				Priority:         domain.PriorityP1,
				SLA:              "7 days",
				AdjustmentReason: "Уязвимость достижима извне, но защищена предварительной аутентификацией/шлюзом (эксплуатация требует валидных учетных данных).",
				Factors:          factors,
			}
		}

		// Rule 4: P2 Medium (INTERNAL loopback or NONE)
		return domain.ContextualRisk{
			Status:           domain.RiskStatusAssessed,
			BaseSeverity:     baseSev,
			BaseScore:        baseScore,
			ContextualLevel:  domain.RiskLevelMedium,
			ContextualScore:  4.5,
			Priority:         domain.PriorityP2,
			SLA:              "Sprint (30 days)",
			AdjustmentReason: "Сетевой доступ из внешней сети отсутствует (слушатель привязан к локальному интерфейсу 127.0.0.1 либо сетевые слушатели отсутствуют). Уязвимость переведена в плановый спринт.",
			Factors:          factors,
		}
	}

	// Fallback for any other verdict
	return domain.ContextualRisk{
		Status:           domain.RiskStatusAssessed,
		BaseSeverity:     baseSev,
		BaseScore:        baseScore,
		ContextualLevel:  domain.RiskLevelUnknown,
		ContextualScore:  baseScore,
		Priority:         domain.PriorityP2,
		SLA:              "Sprint (30 days)",
		AdjustmentReason: "Автоматическая переоценка риска завершена.",
		Factors:          factors,
	}
}

func detectExposure(c *domain.AnalysisCase) string {
	if c == nil {
		return "NONE"
	}

	var hasPublic, hasInternal bool

	// 1. Check Exposures in EvidenceGraph
	facts := c.EvidenceGraph.ExposuresList()
	for _, f := range facts {
		if f.Direction == "inbound" && f.Kind == "listener" {
			switch f.Scope {
			case domain.ScopeAllInterfaces, domain.ScopeHostSpecific:
				hasPublic = true
			case domain.ScopeLoopback, domain.ScopeUnix:
				hasInternal = true
			default:
				if strings.Contains(f.Address, "0.0.0.0") || strings.HasPrefix(f.Address, ":") {
					hasPublic = true
				} else if strings.Contains(f.Address, "127.0.0.1") || strings.Contains(f.Address, "localhost") {
					hasInternal = true
				}
			}
		}
	}

	// 2. Check Evidences in EvidenceGraph
	for _, ev := range c.EvidenceGraph.EvidenceList() {
		content := strings.ToLower(ev.Content)
		if ev.Kind == domain.EvidenceEntrypoint || strings.Contains(ev.Source, "exposure") || strings.Contains(ev.Source, "listener") {
			if strings.Contains(content, "0.0.0.0") || strings.Contains(content, "all-interfaces") {
				hasPublic = true
			} else if strings.Contains(content, "127.0.0.1") || strings.Contains(content, "localhost") || strings.Contains(content, "loopback") {
				hasInternal = true
			}
		}
	}

	if hasPublic {
		return "PUBLIC"
	}
	if hasInternal {
		return "INTERNAL"
	}
	return "NONE"
}

func detectAuthentication(c *domain.AnalysisCase) string {
	if c == nil {
		return "NONE"
	}

	// 1. Check Claims for authentication condition
	for _, cl := range c.Claims {
		cid := string(cl.ConditionID)
		if cl.Result == domain.ClaimTrue {
			if cid == "C-AUTH" || strings.Contains(strings.ToLower(cid), "auth") {
				return "REQUIRED"
			}
		}
	}

	// 2. Check Exposure facts for auth-middleware
	for _, f := range c.EvidenceGraph.ExposuresList() {
		if f.Direction == "inbound" && f.Kind == "auth-middleware" {
			return "REQUIRED"
		}
	}

	// 3. Check Evidence for auth-middleware
	for _, ev := range c.EvidenceGraph.EvidenceList() {
		if strings.Contains(strings.ToLower(ev.Content), "auth") && strings.Contains(strings.ToLower(ev.Content), "middleware") {
			return "REQUIRED"
		}
	}

	return "NONE"
}

func defaultScoreForSeverity(sev string) float64 {
	switch strings.ToUpper(sev) {
	case "CRITICAL", "BLOCKER":
		return 9.8
	case "HIGH":
		return 7.5
	case "MEDIUM", "MODERATE":
		return 5.0
	case "LOW":
		return 3.0
	default:
		return 5.0
	}
}

func defaultSeverityForScore(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}
