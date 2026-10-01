package justification_test

import (
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
	"example.com/vuln-analyzer/internal/justification"
	"example.com/vuln-analyzer/internal/report"
)

func TestJustification_ExploitableGeneratesHumanRemainder(t *testing.T) {
	caseData := &domain.AnalysisCase{
		Vulnerability: domain.Vulnerability{
			ID: "GO-2026-6443",
		},
		Verdict: &domain.VerdictResult{
			Verdict: domain.VerdictExploitable,
		},
		CVEAnalysis: &domain.CVEAnalysisProposal{
			Mechanisms: []domain.DefectMechanism{
				{
					Summary:        "panic in RouteAndProcess",
					FaultingSites:  []string{"xds/server.RouteAndProcess"},
					AuxiliarySites: []string{"transport.HandleStreams"},
				},
			},
		},
	}

	dossier := justification.Build(caseData)
	caseData.Justification = &dossier

	if len(dossier.HumanRemainder) == 0 {
		t.Fatalf("expected human remainder for unconfirmed auxiliary symbol in EXPLOITABLE case")
	}

	trackerText := report.TrackerRationale(caseData)
	if !strings.Contains(trackerText, "xds/server.RouteAndProcess") {
		t.Errorf("expected faulting site in tracker rationale")
	}
	if !strings.Contains(trackerText, "HandleStreams") {
		t.Errorf("expected auxiliary site in human remainder rationale")
	}
}
