// Package llm implements an OpenAI-compatible chat client and the LLM
// adapters plugged into the workflow. Invariant: the model proposes,
// deterministic code verifies — LLM output is never evidence and never
// sets a claim or verdict by itself.
package llm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fedorovmv/izyan/internal/domain"
	"time"
)

// ModelRole selects which configured model to use.
type ModelRole int

const (
	// Analyze is for reasoning-heavy tasks (review, gap analysis).
	Analyze ModelRole = iota
	// Build is for structured generation (root cause, exploit model).
	Build
)

type Config struct {
	BaseURL      string
	APIKey       string
	AnalyzeModel string
	BuildModel   string
	TimeoutSec   int
	MaxTokens    int
	InsecureTLS  bool
	Enabled      bool
	// BuildMaxRetries bounds JSON-repair retries for the build model.
	BuildMaxRetries int
}

// ConfigFromEnv reads LLM_* variables. LLM_ENABLED must be truthy.
func ConfigFromEnv() Config {
	c := Config{
		BaseURL:      os.Getenv("LLM_BASE_URL"),
		APIKey:       os.Getenv("LLM_API_KEY"),
		AnalyzeModel: os.Getenv("LLM_ANALYZE_MODEL"),
		BuildModel:   os.Getenv("LLM_BUILD_MODEL"),
		MaxTokens:    4000,
		TimeoutSec:   120,
	}
	c.Enabled = truthy(os.Getenv("LLM_ENABLED"))
	c.InsecureTLS = truthy(os.Getenv("LLM_INSECURE_TLS"))
	if v, err := strconv.Atoi(os.Getenv("LLM_TIMEOUT_SEC")); err == nil && v > 0 {
		c.TimeoutSec = v
	}
	if v, err := strconv.Atoi(os.Getenv("LLM_MAX_TOKENS")); err == nil && v > 0 {
		c.MaxTokens = v
	}
	if v, err := strconv.Atoi(os.Getenv("LLM_BUILD_MAX_RETRIES")); err == nil && v >= 0 {
		c.BuildMaxRetries = v
	}
	if c.BuildModel == "" {
		c.BuildModel = c.AnalyzeModel
	}
	return c
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// LoadDotEnv loads KEY=VALUE lines from path into the environment without
// overriding variables that are already set.
func LoadDotEnv(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.Trim(strings.TrimSpace(v), `"'`)
		if os.Getenv(k) == "" {
			if err := os.Setenv(k, v); err != nil {
				return err
			}
		}
	}
	return nil
}

type Client struct {
	cfg  Config
	http *http.Client
}

func NewClient(cfg Config) *Client {
	tr := &http.Transport{}
	if cfg.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec -- explicit opt-in for internal endpoints
	}
	return &Client{cfg: cfg, http: &http.Client{
		Timeout:   time.Duration(cfg.TimeoutSec) * time.Second,
		Transport: tr,
	}}
}

// Retries returns how many extra attempts build-model calls get on
// unparseable output (0 = single attempt).
func (c *Client) Retries() int { return c.cfg.BuildMaxRetries }

func (c *Client) modelFor(role ModelRole) string {
	if c == nil {
		return ""
	}
	if role == Build && c.cfg.BuildModel != "" {
		return c.cfg.BuildModel
	}
	return c.cfg.AnalyzeModel
}

// ToolDefinition defines a function tool available to the model.
type ToolDefinition struct {
	Type     string       `json:"type"` // "function"
	Function FunctionSpec `json:"function"`
}

// FunctionSpec describes a tool function signature and schema.
type FunctionSpec struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters,omitempty"`
}

// ToolCall represents a model's request to execute a tool.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // "function"
	Function FunctionCall `json:"function"`
}

// FunctionCall describes the function name and arguments to invoke.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatMessage represents a single message in an OpenAI-compatible chat transcript.
type ChatMessage struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type chatMessage = ChatMessage

type chatRequest struct {
	Model       string           `json:"model"`
	Messages    []ChatMessage    `json:"messages"`
	Temperature float64          `json:"temperature"`
	MaxTokens   int              `json:"max_tokens"`
	Tools       []ToolDefinition `json:"tools,omitempty"`
	ToolChoice  any              `json:"tool_choice,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message      ChatMessage `json:"message"`
		FinishReason string      `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete runs a single-shot chat completion. It returns the message
// content and the provider's finish_reason so callers can tell a
// truncated or filtered response apart from malformed output.
func (c *Client) Complete(ctx context.Context, role ModelRole, system, user string) (string, string, error) {
	return c.CompleteMessages(ctx, role, system, []ChatMessage{{Role: "user", Content: user}})
}

// CompleteMessages runs a multi-turn chat completion: system prompt plus
// the given transcript (used by the bounded agent loop — per condition,
// never a global chat history).
func (c *Client) CompleteMessages(ctx context.Context, role ModelRole, system string, messages []ChatMessage) (string, string, error) {
	msg, finish, err := c.Chat(ctx, role, system, messages, nil)
	return msg.Content, finish, err
}

// Chat runs a chat completion with full message history and optional native tools.
func (c *Client) Chat(ctx context.Context, role ModelRole, system string, messages []ChatMessage, tools []ToolDefinition) (ChatMessage, string, error) {
	if c == nil {
		return ChatMessage{}, "", fmt.Errorf("llm client is nil")
	}
	var allMessages []ChatMessage
	if system != "" {
		allMessages = append(allMessages, ChatMessage{Role: "system", Content: system})
	}
	allMessages = append(allMessages, messages...)
	req := chatRequest{
		Model:       c.modelFor(role),
		Messages:    allMessages,
		Temperature: 0,
		MaxTokens:   c.cfg.MaxTokens,
		Tools:       tools,
	}
	if len(tools) > 0 {
		req.ToolChoice = "auto"
	}
	body, _ := json.Marshal(req)
	url := strings.TrimRight(c.cfg.BaseURL, "/") + "/chat/completions"
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return ChatMessage{}, "", err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.http.Do(hreq)
	if err != nil {
		return ChatMessage{}, "", fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return ChatMessage{}, "", fmt.Errorf("llm read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return ChatMessage{}, "", fmt.Errorf("llm status %d: %.300s", resp.StatusCode, raw)
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return ChatMessage{}, "", fmt.Errorf("llm decode: %w", err)
	}
	if out.Error != nil {
		return ChatMessage{}, "", fmt.Errorf("llm error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return ChatMessage{}, "", fmt.Errorf("llm: empty choices")
	}
	return out.Choices[0].Message, out.Choices[0].FinishReason, nil
}

// ExtractJSON pulls the first JSON object/array out of an LLM response,
// tolerating ```json fences and surrounding prose.
func ExtractJSON(s string) string {
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i:]
		if j := strings.Index(rest, "\n"); j >= 0 {
			rest = rest[j+1:]
			if k := strings.Index(rest, "```"); k >= 0 {
				return strings.TrimSpace(rest[:k])
			}
		}
	}
	startObj := strings.Index(s, "{")
	startArr := strings.Index(s, "[")
	start := -1
	switch {
	case startObj < 0:
		start = startArr
	case startArr < 0:
		start = startObj
	default:
		if startObj < startArr {
			start = startObj
		} else {
			start = startArr
		}
	}
	if start < 0 {
		return ""
	}
	endObj := strings.LastIndex(s, "}")
	endArr := strings.LastIndex(s, "]")
	end := endObj
	if endArr > end {
		end = endArr
	}
	if end <= start {
		return ""
	}
	return strings.TrimSpace(s[start : end+1])
}

// refusalMarkers are phrases providers emit when a safety/policy layer
// declines the request — distinct failure class from malformed output.
var refusalMarkers = []string{
	"blocked by", "content filter", "content_filter",
	"cannot assist", "can't assist", "can't help", "cannot help",
	"unable to fulfill", "against my guidelines", "safety guidelines",
	"use-policy", "violates", "i must refuse", "i'm sorry, but",
}

// DescribeBadOutput classifies model output that failed JSON extraction
// into an actionable reason — provider refusal, empty or truncated
// output, or non-JSON text — suffixed with a bounded snippet of the raw
// response so the failure is diagnosable from the report alone.
func DescribeBadOutput(content, finishReason string) string {
	low := strings.ToLower(content)
	reason := "non-JSON output"
	switch {
	case finishReason == "content_filter" || finishReason == "safety":
		reason = "provider refusal (finish_reason=" + finishReason + ")"
	case strings.TrimSpace(content) == "":
		reason = "empty output"
		if finishReason != "" && finishReason != "stop" {
			reason += " (finish_reason=" + finishReason + ")"
		}
	case hasRefusalMarker(low):
		reason = "provider refusal (content filter)"
	case finishReason == "length":
		reason = "truncated output (finish_reason=length)"
	}
	if snip := outputSnippet(content, 160); snip != "" {
		return reason + ": " + snip
	}
	return reason
}

// IsRefusal reports whether the response is a provider-side refusal
// (safety/policy block or refusal text). A refusal will not self-heal
// on retry with the same prompt — retry loops should stop early.
func IsRefusal(content, finishReason string) bool {
	if finishReason == "content_filter" || finishReason == "safety" {
		return true
	}
	return hasRefusalMarker(strings.ToLower(content))
}

func hasRefusalMarker(low string) bool {
	for _, m := range refusalMarkers {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

func outputSnippet(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// llmBudgetExhausted reports whether the LLM call budget is spent.
// MaxLLMCalls <= 0 means no explicit limit (the default budget lives in
// the CLI wiring); tests and adapters without limits keep working.
func llmBudgetExhausted(c *domain.AnalysisCase) bool {
	max := c.Workflow.Limits.MaxLLMCalls
	return max > 0 && c.UsageSnapshot().LLMCalls >= max
}
