package report

import (
	"encoding/json"
	"strings"
	"testing"

	"example.com/vuln-analyzer/internal/domain"
)

type vexDocOut struct {
	Statements []struct {
		Status          string `json:"status"`
		Justification   string `json:"justification"`
		ImpactStatement string `json:"impact_statement"`
		ActionStatement string `json:"action_statement"`
		Vulnerability   struct {
			ID string `json:"@id"`
		} `json:"vulnerability"`
		Products []struct {
			ID string `json:"@id"`
		} `json:"products"`
		Subcomponents []struct {
			ID string `json:"@id"`
		} `json:"subcomponents"`
	} `json:"statements"`
}

func vexCase(t *testing.T, verdict domain.Verdict) *domain.AnalysisCase {
	t.Helper()
	return &domain.AnalysisCase{
		ID: "case-x",
		Vulnerability: domain.Vulnerability{
			ID:     "GO-2024-0001",
			Module: "example.com/dep",
		},
		Product: domain.ProductSnapshot{
			Repository: t.TempDir(), // no go.mod -> falls back to path
			Commit:     "abc123",
		},
		Affected: &domain.AffectedResult{
			ModulePresent:   domain.ClaimTrue,
			ResolvedVersion: "v1.0.0",
		},
		Verdict: &domain.VerdictResult{Verdict: verdict, Reason: "test reason"},
	}
}

func decodeVex(t *testing.T, c *domain.AnalysisCase) vexDocOut {
	t.Helper()
	b, err := OpenVEX(c)
	if err != nil {
		t.Fatal(err)
	}
	var d vexDocOut
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatalf("invalid OpenVEX json: %v", err)
	}
	if len(d.Statements) != 1 {
		t.Fatalf("statements=%d want 1", len(d.Statements))
	}
	return d
}

func TestOpenVEXExploitable(t *testing.T) {
	d := decodeVex(t, vexCase(t, domain.VerdictExploitable))
	st := d.Statements[0]
	if st.Status != "affected" {
		t.Fatalf("status=%s want affected", st.Status)
	}
	if !strings.HasSuffix(st.Vulnerability.ID, "/vuln/GO-2024-0001") {
		t.Fatalf("vuln ref: %s", st.Vulnerability.ID)
	}
	if len(st.Subcomponents) != 1 ||
		st.Subcomponents[0].ID != "pkg:golang/example.com/dep@v1.0.0" {
		t.Fatalf("subcomponent: %+v", st.Subcomponents)
	}
	if !strings.Contains(st.Products[0].ID, "@abc123") {
		t.Fatalf("product must pin the analyzed commit: %s", st.Products[0].ID)
	}
}

func TestOpenVEXNotAffectedJustifications(t *testing.T) {
	c := vexCase(t, domain.VerdictNotAffected)
	c.Affected.ModulePresent = domain.ClaimFalse
	if st := decodeVex(t, c).Statements[0]; st.Justification != "component_not_present" {
		t.Fatalf("justification=%s", st.Justification)
	}
	c.Affected.ModulePresent = domain.ClaimTrue
	c.Affected.VersionAffected = domain.ClaimFalse
	if st := decodeVex(t, c).Statements[0]; st.Justification != "vulnerable_code_not_present" {
		t.Fatalf("justification=%s", st.Justification)
	}
}

func TestOpenVEXNoPathIsNotAffected(t *testing.T) {
	st := decodeVex(t, vexCase(t, domain.VerdictNoExploitPathFound)).Statements[0]
	if st.Status != "not_affected" ||
		st.Justification != "vulnerable_code_not_in_execute_path" {
		t.Fatalf("got %+v", st)
	}
}

func TestOpenVEXInconclusiveIsUnderInvestigation(t *testing.T) {
	for _, v := range []domain.Verdict{domain.VerdictInconclusive} {
		st := decodeVex(t, vexCase(t, v)).Statements[0]
		if st.Status != "under_investigation" || st.ActionStatement == "" {
			t.Fatalf("verdict %s: %+v", v, st)
		}
		if st.Justification != "" {
			t.Fatalf("under_investigation must not carry a justification: %+v", st)
		}
	}
}
