package tracker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTicketEmbeddedOSV(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "t.json")
	osv := `{"id":"GHSA-x","affected":[]}`
	if err := os.WriteFile(p, []byte(`{"vulnerability":"GHSA-x","osv":`+osv+`}`), 0o644); err != nil {
		t.Fatal(err)
	}
	tk, err := LoadTicket(p)
	if err != nil {
		t.Fatal(err)
	}
	f, err := tk.AdvisoryFile(dir, "GHSA-x")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(f)
	if string(b) != osv {
		t.Fatalf("embedded osv not materialized: %s", b)
	}
}

func TestTicketSynthAdvisory(t *testing.T) {
	tk := &Ticket{
		Module:        "example.com/dep",
		Imports:       []string{"example.com/dep/vuln"},
		Symbols:       []string{"example.com/dep/vuln.Parse"},
		FixedVersions: []string{"v1.0.1"},
	}
	f, err := tk.AdvisoryFile(t.TempDir(), "TEAM-1")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ID       string `json:"id"`
		Affected []struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			EcosystemSpecific struct {
				Imports []struct {
					Path    string   `json:"path"`
					Symbols []string `json:"symbols"`
				} `json:"imports"`
			} `json:"ecosystem_specific"`
			Ranges []struct {
				Events []map[string]string `json:"events"`
			} `json:"ranges"`
		} `json:"affected"`
	}
	b, _ := os.ReadFile(f)
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.ID != "TEAM-1" || doc.Affected[0].Package.Name != "example.com/dep" {
		t.Fatalf("bad synth doc: %s", b)
	}
	imp := doc.Affected[0].EcosystemSpecific.Imports[0]
	if imp.Path != "example.com/dep/vuln" || len(imp.Symbols) != 1 || imp.Symbols[0] != "Parse" {
		t.Fatalf("bad imports: %+v", imp)
	}
	ev := doc.Affected[0].Ranges[0].Events
	if ev[0]["introduced"] != "0" || ev[1]["fixed"] != "v1.0.1" {
		t.Fatalf("bad events: %+v", ev)
	}
}

func TestTicketNoAdvisory(t *testing.T) {
	tk := &Ticket{Vulnerability: "GHSA-y"}
	f, err := tk.AdvisoryFile(t.TempDir(), "GHSA-y")
	if err != nil || f != "" {
		t.Fatalf("want no advisory file, got %q %v", f, err)
	}
}
