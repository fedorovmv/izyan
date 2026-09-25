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

	"example.com/vuln-analyzer/internal/domain"
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

func (c *Client) modelFor(role ModelRole) string {
	if role == Build && c.cfg.BuildModel != "" {
		return c.cfg.BuildModel
	}
	return c.cfg.AnalyzeModel
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
	MaxTokens   int           `json:"max_tokens"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Complete runs a single-shot chat completion.
func (c *Client) Complete(ctx context.Context, role ModelRole, system, user string) (string, error) {
	req := chatRequest{
		Model: c.modelFor(role),
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Temperature: 0,
		MaxTokens:   c.cfg.MaxTokens,
	}
	body, _ := json.Marshal(req)
	url := strings.TrimRight(c.cfg.BaseURL, "/") + "/chat/completions"
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	hreq.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		hreq.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.http.Do(hreq)
	if err != nil {
		return "", fmt.Errorf("llm request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("llm read: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("llm status %d: %.300s", resp.StatusCode, raw)
	}
	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("llm decode: %w", err)
	}
	if out.Error != nil {
		return "", fmt.Errorf("llm error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("llm: empty choices")
	}
	return out.Choices[0].Message.Content, nil
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

// llmBudgetExhausted reports whether the LLM call budget is spent.
// MaxLLMCalls <= 0 means no explicit limit (the default budget lives in
// the CLI wiring); tests and adapters without limits keep working.
func llmBudgetExhausted(c *domain.AnalysisCase) bool {
	max := c.Workflow.Limits.MaxLLMCalls
	return max > 0 && c.Workflow.Usage.LLMCalls >= max
}
