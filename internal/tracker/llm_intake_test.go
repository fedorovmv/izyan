package tracker

import (
	"context"
	"os"
	"strings"
	"testing"
)

type mockCompleter struct {
	response string
	err      error
}

func (m mockCompleter) Complete(ctx context.Context, system, user string) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	return m.response, nil
}

func TestExtractTicketWithLLM_Success(t *testing.T) {
	rawText := `Коллеги, по задаче SEC-777 в компоненте GATEWAY обнаружена уязвимость GO-2026-4950 (также известна как CVE-2026-1000) в библиотеке github.com/valyala/fasthttp версии v1.47.0. Просьба проверить.`

	mockResp := `{
		"vulnerability": "GO-2026-4950",
		"aliases": ["CVE-2026-1000"],
		"ticket_id": "SEC-777",
		"package": "github.com/valyala/fasthttp",
		"version": "v1.47.0",
		"component": "GATEWAY",
		"summary": "Проверка уязвимости в fasthttp"
	}`

	completer := mockCompleter{response: mockResp}
	tk, err := ExtractTicketWithLLM(context.Background(), completer, rawText)
	if err != nil {
		t.Fatalf("ExtractTicketWithLLM error: %v", err)
	}

	if tk.ID != "SEC-777" {
		t.Errorf("ID = %q, want SEC-777", tk.ID)
	}
	if tk.Vulnerability != "GO-2026-4950" {
		t.Errorf("Vulnerability = %q, want GO-2026-4950", tk.Vulnerability)
	}
	if len(tk.Aliases) == 0 || tk.Aliases[0] != "CVE-2026-1000" {
		t.Errorf("Aliases = %v, want [CVE-2026-1000]", tk.Aliases)
	}
	if tk.Package != "github.com/valyala/fasthttp" {
		t.Errorf("Package = %q, want github.com/valyala/fasthttp", tk.Package)
	}
	if tk.Component != "GATEWAY" {
		t.Errorf("Component = %q, want GATEWAY", tk.Component)
	}
	if tk.Version != "v1.47.0" {
		t.Errorf("Version = %q, want v1.47.0", tk.Version)
	}
}

func TestExtractTicketWithLLM_FencedJSON(t *testing.T) {
	rawText := `Please analyze CVE-2026-77406 in amqp091-go for issue JIRA-42`

	mockResp := "Here is the extracted result:\n```json\n" + `{
		"vulnerability": "CVE-2026-77406",
		"ticket_id": "JIRA-42",
		"package": "github.com/rabbitmq/amqp091-go",
		"summary": "AMQP issue"
	}` + "\n```\nHope that helps!"

	completer := mockCompleter{response: mockResp}
	tk, err := ExtractTicketWithLLM(context.Background(), completer, rawText)
	if err != nil {
		t.Fatalf("ExtractTicketWithLLM error: %v", err)
	}

	if tk.Vulnerability != "CVE-2026-77406" {
		t.Errorf("Vulnerability = %q, want CVE-2026-77406", tk.Vulnerability)
	}
	if tk.ID != "JIRA-42" {
		t.Errorf("ID = %q, want JIRA-42", tk.ID)
	}
}

func TestExtractTicketWithLLM_AntiHallucination(t *testing.T) {
	rawText := `Please review the logs for the morning incident`

	// LLM hallucinates an ID that doesn't appear anywhere in rawText
	mockResp := `{
		"vulnerability": "CVE-1999-9999",
		"ticket_id": "FAKE-1"
	}`

	completer := mockCompleter{response: mockResp}
	_, err := ExtractTicketWithLLM(context.Background(), completer, rawText)
	if err == nil {
		t.Fatalf("expected error for hallucinated vulnerability ID, got nil")
	}
	if !strings.Contains(err.Error(), "does not appear in source text") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestExtractTicketWithLLM_PunctuationTolerance(t *testing.T) {
	rawText := `Check vuln CVE 2026 4950 in payment service`

	mockResp := `{
		"vulnerability": "CVE-2026-4950",
		"component": "payment"
	}`

	completer := mockCompleter{response: mockResp}
	tk, err := ExtractTicketWithLLM(context.Background(), completer, rawText)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tk.Vulnerability != "CVE-2026-4950" {
		t.Errorf("Vulnerability = %q, want CVE-2026-4950", tk.Vulnerability)
	}
}

func TestLoadTicketWithOptions_Fallback(t *testing.T) {
	// Text without regex-friendly labels:
	rawText := `Коллеги, гляньте задачу SEC-889 по уязвимости CVE-2026-77406 в rabbitmq-amqp`

	mockResp := `{
		"vulnerability": "CVE-2026-77406",
		"ticket_id": "SEC-889",
		"package": "github.com/rabbitmq/amqp091-go",
		"component": "MESSAGE_BROKER"
	}`

	completer := mockCompleter{response: mockResp}
	tmpFile := t.TempDir() + "/chat.txt"
	if err := os.WriteFile(tmpFile, []byte(rawText), 0o644); err != nil {
		t.Fatal(err)
	}

	tk, err := LoadTicketWithOptions(tmpFile, "", completer)
	if err != nil {
		t.Fatalf("LoadTicketWithOptions error: %v", err)
	}

	if tk.ID != "SEC-889" {
		t.Errorf("ID = %q, want SEC-889", tk.ID)
	}
	if tk.Vulnerability != "CVE-2026-77406" {
		t.Errorf("Vulnerability = %q, want CVE-2026-77406", tk.Vulnerability)
	}
	if tk.Package != "github.com/rabbitmq/amqp091-go" {
		t.Errorf("Package = %q, want github.com/rabbitmq/amqp091-go", tk.Package)
	}
	if tk.Component != "MESSAGE_BROKER" {
		t.Errorf("Component = %q, want MESSAGE_BROKER", tk.Component)
	}
}

func TestExtractTicketWithLLM_WithGoVersion(t *testing.T) {
	rawText := `В задаче SEC-999 для сервиса AUTH обнаружена CVE-2026-77405 в amqp091-go v1.10.0. Сервис собран на Go 1.22.4.`
	mockResp := `{
		"vulnerability": "CVE-2026-77405",
		"ticket_id": "SEC-999",
		"package": "github.com/rabbitmq/amqp091-go",
		"version": "v1.10.0",
		"component": "AUTH",
		"go_version": "go1.22.4",
		"summary": "TLS min version weakness in amqp"
	}`
	completer := mockCompleter{response: mockResp}
	tk, err := ExtractTicketWithLLM(context.Background(), completer, rawText)
	if err != nil {
		t.Fatalf("ExtractTicketWithLLM failed: %v", err)
	}
	if tk.GoVersion != "go1.22.4" {
		t.Fatalf("expected GoVersion go1.22.4, got %q", tk.GoVersion)
	}
}
