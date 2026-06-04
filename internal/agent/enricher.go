// Package agent contains the AI enrichment layer.
// It calls the Claude API to produce a structured risk report for an outdated
// Helm release: upgrade path, breaking changes, CVEs fixed, and a risk score.
package agent

import (
	"context"
	"encoding/json"
	"fmt"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// RiskReport is the structured output produced by the AI enricher.
// It is stored in HelmEOLAlertStatus and forwarded to notification channels.
type RiskReport struct {
	// UpgradePath is the recommended step-by-step version sequence to follow,
	// e.g. "13.0.0 → 18.0.0 → 24.0.2 — skip 16.x (CRD removal in 17.0)".
	UpgradePath string `json:"upgradePath"`

	// RiskScore is 1–10. 1 = safe minor patch, 10 = critical CVE / data-loss risk.
	RiskScore int `json:"riskScore"`

	// BreakingChanges lists API removals, config renames, or behaviour changes
	// that require action before upgrading.
	BreakingChanges []string `json:"breakingChanges"`

	// CVEsFixed lists CVE identifiers addressed in versions newer than the installed one.
	CVEsFixed []string `json:"cvesFixed"`

	// RecommendedAction is one of:
	//   "upgrade" — safe to upgrade on next maintenance window
	//   "urgent"  — CVE or critical bug, upgrade ASAP
	//   "hold"    — known issues with target version, wait for a patch
	RecommendedAction string `json:"recommendedAction"`

	// Summary is a 2-3 sentence human-readable overview for the notification message.
	Summary string `json:"summary"`
}

// AIEnricher calls the Claude API to produce a RiskReport for an outdated release.
// Create one instance at startup and reuse it across reconcile calls.
type AIEnricher struct {
	client anthropic.Client
	model  string
}

// NewAIEnricher constructs an AIEnricher using the provided Anthropic API key.
// The API key should come from a Kubernetes Secret mounted as an env var —
// never hard-code it or commit it to git.
//
// The constructor option lives in the "option" sub-package, not the root package.
// This is the standard pattern in the Anthropic Go SDK.
func NewAIEnricher(apiKey string) *AIEnricher {
	return &AIEnricher{
		client: anthropic.NewClient(
			option.WithAPIKey(apiKey), // option sub-package, not anthropic.WithAPIKey
		),
		// claude-sonnet-4-6 gives the best balance of speed and quality for
		// structured analysis tasks. Swap to claude-opus-4-6 for deeper research.
		model: "claude-sonnet-4-6",
	}
}

// riskReportTool defines the tool Claude will call to return structured data.
// By defining the output as a tool, Claude is forced to return structured JSON
// rather than free-form prose — much more reliable than asking it to "return JSON".
//
// The SDK wraps ToolParam in ToolUnionParam because the API also supports
// built-in tools (BashTool, TextEditorTool, etc.) alongside custom tools.
// Our custom tool uses the OfTool field.
var riskReportTool = anthropic.ToolUnionParam{
	OfTool: &anthropic.ToolParam{
		Name:        "report_risk",
		Description: anthropic.String("Report the risk assessment and upgrade path for an outdated Helm chart"),
		InputSchema: anthropic.ToolInputSchemaParam{
			Properties: map[string]interface{}{
				"upgradePath": map[string]interface{}{
					"type":        "string",
					"description": "Step-by-step version sequence to upgrade safely, with notes on intermediate stops required",
				},
				"riskScore": map[string]interface{}{
					"type":        "integer",
					"minimum":     1,
					"maximum":     10,
					"description": "Overall risk score: 1=trivial patch, 10=critical CVE or data loss risk",
				},
				"breakingChanges": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
					"description": "Breaking changes, API removals, or config renames between installed and latest versions",
				},
				"cvesFixed": map[string]interface{}{
					"type": "array",
					"items": map[string]interface{}{
						"type": "string",
					},
					"description": "CVE identifiers fixed in versions newer than the installed version",
				},
				"recommendedAction": map[string]interface{}{
					"type":        "string",
					"enum":        []string{"upgrade", "urgent", "hold"},
					"description": "upgrade=safe on next window, urgent=CVE/critical fix, hold=known issues with target",
				},
				"summary": map[string]interface{}{
					"type":        "string",
					"description": "2-3 sentence human-readable summary for the notification message",
				},
			},
			Required: []string{"upgradePath", "riskScore", "breakingChanges", "cvesFixed", "recommendedAction", "summary"},
		},
	},
}

// Enrich calls the Claude API and returns a structured RiskReport for the given
// outdated Helm release.
func (e *AIEnricher) Enrich(
	ctx context.Context,
	chartName, installedVersion, latestVersion, severity string,
	versionsBehind int,
) (*RiskReport, error) {
	prompt := fmt.Sprintf(`You are a Kubernetes platform engineer performing an upgrade risk assessment.

A Helm chart is outdated and needs to be evaluated:
- Chart:             %s
- Installed version: %s
- Latest version:    %s
- Severity:          %s (%d versions behind)

Please analyse:
1. The safest upgrade path (are there intermediate versions required, e.g. to run DB migrations?)
2. Breaking changes between installed and latest (API removals, default value changes, CRD changes)
3. Any CVEs fixed in newer versions
4. An overall risk score (1–10) considering: breaking changes, CVEs, size of version jump
5. A recommended action (upgrade / urgent / hold)
6. A short summary (2-3 sentences) for a Teams or PagerDuty notification

Use the report_risk tool to return your assessment as structured data.`,
		chartName, installedVersion, latestVersion, severity, versionsBehind,
	)

	msg, err := e.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(e.model),
		MaxTokens: 1024,
		// Tools is []ToolUnionParam — the union type allows both custom tools
		// (OfTool) and Anthropic built-in tools (e.g. OfBashTool20241022).
		Tools: []anthropic.ToolUnionParam{riskReportTool},
		// ToolChoiceParamOfTool forces Claude to call exactly the named tool.
		// The SDK provides this helper so we don't have to construct the union manually.
		// Real field names in ToolChoiceUnionParam are: OfAuto, OfAny, OfTool, OfNone.
		ToolChoice: anthropic.ToolChoiceParamOfTool("report_risk"),
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(prompt)),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("calling claude API for chart %s: %w", chartName, err)
	}

	// Find the tool_use content block in the response.
	// block.JSON.Input is the SDK's raw field accessor — Raw() returns the JSON
	// as a string (not []byte), so we convert explicitly.
	for _, block := range msg.Content {
		if block.Type == "tool_use" {
			return parseToolResult([]byte(block.JSON.Input.Raw()))
		}
	}
	return nil, fmt.Errorf("claude did not return a tool_use block for chart %s", chartName)
}

// parseToolResult decodes the raw JSON from the tool_use block into a RiskReport.
func parseToolResult(raw []byte) (*RiskReport, error) {
	var report RiskReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("decoding risk report JSON: %w", err)
	}
	if report.RiskScore < 1 || report.RiskScore > 10 {
		return nil, fmt.Errorf("risk score %d out of range 1-10", report.RiskScore)
	}
	return &report, nil
}
