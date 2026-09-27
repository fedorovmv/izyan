package report

import (
	"encoding/json"
	"fmt"

	"example.com/vuln-analyzer/internal/domain"
)

// CycloneDX VEX export (spec 1.5). Like the OpenVEX document this is a
// projection of the internal verdict — never a source (spec §25).
//
// Verdict → analysis mapping:
//
//	EXPLOITABLE            → exploitable
//	NOT_AFFECTED           → not_affected + justification
//	NO_EXPLOIT_PATH_FOUND  → not_affected + code_not_reachable
//	                         (issued only after negative verification ran)
//	INCONCLUSIVE / none    → in_triage + detail
type cdxDoc struct {
	BOMFormat       string             `json:"bomFormat"`
	SpecVersion     string             `json:"specVersion"`
	SerialNumber    string             `json:"serialNumber"`
	Version         int                `json:"version"`
	Metadata        cdxMetadata        `json:"metadata"`
	Components      []cdxComponent     `json:"components,omitempty"`
	Vulnerabilities []cdxVulnerability `json:"vulnerabilities"`
}

type cdxMetadata struct {
	Timestamp string       `json:"timestamp"`
	Component cdxComponent `json:"component,omitempty"`
}

type cdxComponent struct {
	BOMRef string `json:"bom-ref,omitempty"`
	Type   string `json:"type,omitempty"`
	Name   string `json:"name,omitempty"`
	PURL   string `json:"purl,omitempty"`
}

type cdxVulnerability struct {
	ID       string      `json:"id"`
	Source   cdxSource   `json:"source"`
	Affects  []cdxAffect `json:"affects,omitempty"`
	Analysis cdxAnalysis `json:"analysis"`
}

type cdxSource struct {
	Name string `json:"name"`
	URL  string `json:"url,omitempty"`
}

type cdxAffect struct {
	Ref string `json:"ref"`
}

type cdxAnalysis struct {
	State         string `json:"state"`
	Justification string `json:"justification,omitempty"`
	Detail        string `json:"detail,omitempty"`
}

// CycloneDX renders the case into a CycloneDX VEX document.
func CycloneDX(c *domain.AnalysisCase) ([]byte, error) {
	product := productRef(c.Product)
	var comp *cdxComponent
	var affects []cdxAffect
	if c.Vulnerability.Module != "" {
		purl := "pkg:golang/" + c.Vulnerability.Module
		if v := resolvedVersion(c); v != "" {
			purl += "@" + v
		}
		comp = &cdxComponent{
			BOMRef: purl,
			Type:   "library",
			Name:   c.Vulnerability.Module,
			PURL:   purl,
		}
		affects = []cdxAffect{{Ref: product}}
	}
	reason := ""
	var verdict domain.Verdict
	if c.Verdict != nil {
		verdict = c.Verdict.Verdict
		reason = c.Verdict.Reason
	}
	an := cdxAnalysis{Detail: reason}
	switch verdict {
	case domain.VerdictExploitable:
		an.State = "exploitable"
	case domain.VerdictNotAffected:
		an.State = "not_affected"
		an.Justification = cycloneJustification(c)
	case domain.VerdictNoExploitPathFound:
		an.State = "not_affected"
		an.Justification = "code_not_reachable"
	default:
		an.State = "in_triage"
		if an.Detail == "" {
			an.Detail = "analysis inconclusive — manual review required"
		}
	}
	source := "OSV"
	if len(c.Vulnerability.ID) >= 3 && c.Vulnerability.ID[:3] == "GO-" {
		source = "Go Vulnerability Database"
	}
	vuln := cdxVulnerability{
		ID:       c.Vulnerability.ID,
		Source:   cdxSource{Name: source, URL: vulnRef(c.Vulnerability.ID)},
		Affects:  affects,
		Analysis: an,
	}
	doc := cdxDoc{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.5",
		SerialNumber: fmt.Sprintf("urn:uuid:vuln-analyzer-%s", c.ID),
		Version:      1,
		Metadata: cdxMetadata{
			Timestamp: vexTimestamp(c),
			Component: cdxComponent{
				BOMRef: product,
				Type:   "application",
				Name:   product,
				PURL:   product,
			},
		},
		Vulnerabilities: []cdxVulnerability{vuln},
	}
	if comp != nil {
		doc.Components = []cdxComponent{*comp}
	}
	return json.MarshalIndent(doc, "", "  ")
}

// cycloneJustification maps NOT_AFFECTED sub-reasons to CycloneDX
// justification vocabulary.
func cycloneJustification(c *domain.AnalysisCase) string {
	if c.Affected != nil {
		switch {
		case c.Affected.ModulePresent == domain.ClaimFalse,
			c.Affected.BuildRelevant == domain.ClaimFalse,
			c.Affected.VersionAffected == domain.ClaimFalse,
			c.Affected.PackagePresent == domain.ClaimFalse:
			return "code_not_present"
		}
	}
	return "code_not_present"
}
