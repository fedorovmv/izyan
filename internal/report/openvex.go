package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fedorovmv/izyan/internal/domain"
)

// OpenVEX export (openvex.dev/ns/v0.2.0). The internal verdict model is
// independent of VEX per spec §25 — this is a projection, not a source.
//
// Verdict → status mapping:
//
//	EXPLOITABLE            → affected
//	NOT_AFFECTED           → not_affected + justification
//	NO_EXPLOIT_PATH_FOUND  → not_affected + vulnerable_code_not_in_execute_path
//	                         (issued only after negative verification ran)
//	INCONCLUSIVE / none    → under_investigation + action_statement
type vexDoc struct {
	Context    string         `json:"@context"`
	ID         string         `json:"@id"`
	Author     string         `json:"author"`
	Timestamp  string         `json:"timestamp"`
	Version    int            `json:"version"`
	Statements []vexStatement `json:"statements"`
}

type vexStatement struct {
	Vulnerability   vexComponent   `json:"vulnerability"`
	Products        []vexComponent `json:"products"`
	Subcomponents   []vexComponent `json:"subcomponents,omitempty"`
	Status          string         `json:"status"`
	Justification   string         `json:"justification,omitempty"`
	ImpactStatement string         `json:"impact_statement,omitempty"`
	ActionStatement string         `json:"action_statement,omitempty"`
}

type vexComponent struct {
	ID   string `json:"@id,omitempty"`
	Name string `json:"name,omitempty"`
}

// OpenVEX renders the case into an OpenVEX JSON document.
func OpenVEX(c *domain.AnalysisCase) ([]byte, error) {
	st := vexStatement{
		Vulnerability: vexComponent{ID: vulnRef(c.Vulnerability.ID), Name: c.Vulnerability.ID},
		Products:      []vexComponent{{ID: productRef(c.Product)}},
	}
	if c.Vulnerability.Module != "" {
		sub := "pkg:golang/" + c.Vulnerability.Module
		if v := resolvedVersion(c); v != "" {
			sub += "@" + v
		}
		st.Subcomponents = []vexComponent{{ID: sub}}
	}
	reason := ""
	if c.Verdict != nil {
		reason = c.Verdict.Reason
	}
	var verdict domain.Verdict
	if c.Verdict != nil {
		verdict = c.Verdict.Verdict
	}
	switch verdict {
	case domain.VerdictExploitable:
		st.Status = "affected"
		st.ImpactStatement = reason
	case domain.VerdictNotAffected:
		st.Status = "not_affected"
		st.Justification = notAffectedJustification(c)
		st.ImpactStatement = reason
	case domain.VerdictNoExploitPathFound:
		// Only reached when a FALSE claim survived negative verification —
		// the OpenVEX justification for exactly this situation.
		st.Status = "not_affected"
		st.Justification = "vulnerable_code_not_in_execute_path"
		st.ImpactStatement = reason
	default:
		st.Status = "under_investigation"
		st.ActionStatement = "analysis inconclusive — manual review required"
		if reason != "" {
			st.ActionStatement += ": " + reason
		}
	}
	doc := vexDoc{
		Context:    "https://openvex.dev/ns/v0.2.0",
		ID:         fmt.Sprintf("urn:izyan:case:%s:openvex", c.ID),
		Author:     "izyan",
		Timestamp:  vexTimestamp(c),
		Version:    1,
		Statements: []vexStatement{st},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func notAffectedJustification(c *domain.AnalysisCase) string {
	if c.Affected != nil {
		switch {
		case c.Affected.ModulePresent == domain.ClaimFalse,
			c.Affected.BuildRelevant == domain.ClaimFalse:
			return "component_not_present"
		case c.Affected.VersionAffected == domain.ClaimFalse,
			c.Affected.PackagePresent == domain.ClaimFalse:
			return "vulnerable_code_not_present"
		}
	}
	return "component_not_present"
}

// vulnRef links GO-* ids to the Go vuln DB, everything else to OSV.
func vulnRef(id string) string {
	if strings.HasPrefix(id, "GO-") {
		return "https://pkg.go.dev/vuln/" + id
	}
	return "https://osv.dev/vulnerability/" + id
}

// productRef identifies the analyzed product: module path from go.mod
// (purl) at the analyzed commit, falling back to the repo path.
func productRef(p domain.ProductSnapshot) string {
	name := p.Repository
	if mod := modulePath(p.Repository); mod != "" {
		name = mod
	}
	id := "pkg:golang/" + name
	if p.Commit != "" {
		id += "@" + p.Commit
	}
	return id
}

func resolvedVersion(c *domain.AnalysisCase) string {
	if c.Affected == nil {
		return ""
	}
	return c.Affected.ResolvedVersion
}

func modulePath(repo string) string {
	b, err := os.ReadFile(filepath.Join(repo, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}

func vexTimestamp(c *domain.AnalysisCase) string {
	if !c.Workflow.UpdatedAt.IsZero() {
		return c.Workflow.UpdatedAt.UTC().Format(time.RFC3339)
	}
	return time.Now().UTC().Format(time.RFC3339)
}
