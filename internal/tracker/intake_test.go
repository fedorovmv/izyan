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

func TestParseCustomJSONTicket(t *testing.T) {
	raw := `{
		"code": "SEC-1001",
		"vulnerability_identifier": ["GO-2026-4950", "BDU:2026-0001"],
		"vulnerable_package": ["github.com/valyala/fasthttp"],
		"version_vulnerable_package": ["v1.47.0"],
		"component_code": ["GATEWAY"],
		"product_code": "PROXY",
		"summary": "Potential issue in component",
		"description_plain": "Sample description text",
		"analyst_result": "Analyst note on methods"
	}`

	tk, err := ParseTicket([]byte(raw))
	if err != nil {
		t.Fatalf("ParseTicket error: %v", err)
	}

	if tk.ID != "SEC-1001" {
		t.Errorf("ID = %q, want SEC-1001", tk.ID)
	}
	if tk.Vulnerability != "GO-2026-4950" {
		t.Errorf("Vulnerability = %q, want GO-2026-4950", tk.Vulnerability)
	}
	if len(tk.Aliases) == 0 || tk.Aliases[0] != "BDU:2026-0001" {
		t.Errorf("Aliases = %v, want [BDU:2026-0001]", tk.Aliases)
	}
	if tk.Package != "github.com/valyala/fasthttp" {
		t.Errorf("Package = %q, want github.com/valyala/fasthttp", tk.Package)
	}
	if tk.Module != "github.com/valyala/fasthttp" {
		t.Errorf("Module = %q, want github.com/valyala/fasthttp", tk.Module)
	}
	if tk.Version != "v1.47.0" {
		t.Errorf("Version = %q, want v1.47.0", tk.Version)
	}
	if tk.Component != "GATEWAY" {
		t.Errorf("Component = %q, want GATEWAY", tk.Component)
	}
	if tk.Product != "PROXY" {
		t.Errorf("Product = %q, want PROXY", tk.Product)
	}
	if tk.Rationale != "Analyst note on methods" {
		t.Errorf("Rationale = %q, want 'Analyst note on methods'", tk.Rationale)
	}
}

func TestParseCustomJSONArray(t *testing.T) {
	raw := `[
		{
			"code": "APP-1001",
			"vulnerability_identifier": ["GO-2026-4950"],
			"component": ["GATEWAY"]
		},
		{
			"code": "APP-1002",
			"vulnerability_identifier": ["CVE-2026-77406"],
			"component": ["CORE"]
		}
	]`

	dir := t.TempDir()
	p := filepath.Join(dir, "tickets.json")
	if err := os.WriteFile(p, []byte(raw), 0o644); err != nil {
		t.Fatal(err)
	}

	// Default: returns first ticket
	t1, err := LoadTicket(p)
	if err != nil {
		t.Fatalf("LoadTicket failed: %v", err)
	}
	if t1.ID != "APP-1001" || t1.Vulnerability != "GO-2026-4950" {
		t.Errorf("t1 = %+v, want APP-1001 / GO-2026-4950", t1)
	}

	// Select by ticket ID
	t2, err := LoadTicketWithID(p, "APP-1002")
	if err != nil {
		t.Fatalf("LoadTicketWithID failed: %v", err)
	}
	if t2.ID != "APP-1002" || t2.Vulnerability != "CVE-2026-77406" {
		t.Errorf("t2 = %+v, want APP-1002 / CVE-2026-77406", t2)
	}

	// Not found
	if _, err := LoadTicketWithID(p, "APP-9999"); err == nil {
		t.Errorf("expected error for non-existent ticket ID")
	}
}

func TestParseRawTextTicket_Russian(t *testing.T) {
	text := `Внимание: тикет JIRA-538506
Версия продукта: Demo Service 2.6.0-release
Компонент: GATEWAY 6.5.0-release
Библиотека: github.com/valyala/fasthttp v1.47.0
Алиасы на уязвимость: GO-2026-4950
Описание уязвимости: In github.com/valyala/fasthttp before 1.70.0, ServeFile and ServeFS reinterpret paths.
`

	tk, err := ParseTicket([]byte(text))
	if err != nil {
		t.Fatalf("ParseTicket error: %v", err)
	}

	if tk.ID != "JIRA-538506" {
		t.Errorf("ID = %q, want JIRA-538506", tk.ID)
	}
	if tk.Vulnerability != "GO-2026-4950" {
		t.Errorf("Vulnerability = %q, want GO-2026-4950", tk.Vulnerability)
	}
	if tk.Package != "github.com/valyala/fasthttp" {
		t.Errorf("Package = %q, want github.com/valyala/fasthttp", tk.Package)
	}
	if tk.Component != "GATEWAY 6.5.0-release" {
		t.Errorf("Component = %q, want 'GATEWAY 6.5.0-release'", tk.Component)
	}
	if tk.Release != "Demo Service 2.6.0-release" {
		t.Errorf("Release = %q, want 'Demo Service 2.6.0-release'", tk.Release)
	}
}

func TestParseRawTextTicket_English(t *testing.T) {
	text := `Issue Tracker: JIRA-5432
Product Version: Gateway 3.0
Component: PROXY
Package: github.com/rabbitmq/amqp091-go
Version: 1.10.0
Found vulnerability: CVE-2026-77406 (GHSA-rm6m-hrcw-jw33)
`

	tk, err := ParseTicket([]byte(text))
	if err != nil {
		t.Fatalf("ParseTicket error: %v", err)
	}

	if tk.ID != "JIRA-5432" {
		t.Errorf("ID = %q, want JIRA-5432", tk.ID)
	}
	if tk.Vulnerability != "CVE-2026-77406" {
		t.Errorf("Vulnerability = %q, want CVE-2026-77406", tk.Vulnerability)
	}
	if len(tk.Aliases) == 0 || tk.Aliases[0] != "GHSA-RM6M-HRCW-JW33" {
		t.Errorf("Aliases = %v, want [GHSA-RM6M-HRCW-JW33]", tk.Aliases)
	}
	if tk.Package != "github.com/rabbitmq/amqp091-go" {
		t.Errorf("Package = %q, want github.com/rabbitmq/amqp091-go", tk.Package)
	}
	if tk.Component != "PROXY" {
		t.Errorf("Component = %q, want PROXY", tk.Component)
	}
}

func TestRepoMapResolution(t *testing.T) {
	dir := t.TempDir()

	// 1. Structured format
	structMap := `{
		"components": {
			"GATEWAY": "/repos/gateway",
			"CORE": "/repos/core"
		},
		"products": {
			"PROXY": "/repos/proxy"
		},
		"tickets": {
			"APP-9999": "/repos/special-repo"
		}
	}`
	p1 := filepath.Join(dir, "repos_struct.json")
	if err := os.WriteFile(p1, []byte(structMap), 0o644); err != nil {
		t.Fatal(err)
	}
	rm1, err := LoadRepoMap(p1)
	if err != nil {
		t.Fatalf("LoadRepoMap struct failed: %v", err)
	}

	t1 := &Ticket{Component: "GATEWAY 6.5.0", ID: "APP-1001"}
	if got := rm1.Resolve(t1); got != "/repos/gateway" {
		t.Errorf("Resolve t1 = %q, want /repos/gateway", got)
	}

	t2 := &Ticket{Product: "PROXY", ID: "APP-1002"}
	if got := rm1.Resolve(t2); got != "/repos/proxy" {
		t.Errorf("Resolve t2 = %q, want /repos/proxy", got)
	}

	t3 := &Ticket{ID: "APP-9999"}
	if got := rm1.Resolve(t3); got != "/repos/special-repo" {
		t.Errorf("Resolve t3 = %q, want /repos/special-repo", got)
	}

	// 2. Flat format
	flatMap := `{
		"GATEWAY": "/repos/gateway",
		"APP-1002": "/repos/flat-repo"
	}`
	p2 := filepath.Join(dir, "repos_flat.json")
	if err := os.WriteFile(p2, []byte(flatMap), 0o644); err != nil {
		t.Fatal(err)
	}
	rm2, err := LoadRepoMap(p2)
	if err != nil {
		t.Fatalf("LoadRepoMap flat failed: %v", err)
	}

	if got := rm2.Resolve(t1); got != "/repos/gateway" {
		t.Errorf("Resolve flat t1 = %q, want /repos/gateway", got)
	}
	if got := rm2.Resolve(&Ticket{ID: "APP-1002"}); got != "/repos/flat-repo" {
		t.Errorf("Resolve flat t2 = %q, want /repos/flat-repo", got)
	}
}

func TestParseTicket_GoVersion(t *testing.T) {
	text := `ticket: SEC-888
vulnerability: CVE-2026-77405
package: github.com/rabbitmq/amqp091-go
go_version: go1.22.5
`
	tickets, err := ParseTickets([]byte(text))
	if err != nil {
		t.Fatalf("ParseTickets failed: %v", err)
	}
	if len(tickets) != 1 {
		t.Fatalf("expected 1 ticket, got %d", len(tickets))
	}
	if tickets[0].GoVersion != "go1.22.5" {
		t.Fatalf("expected GoVersion go1.22.5, got %q", tickets[0].GoVersion)
	}
}

