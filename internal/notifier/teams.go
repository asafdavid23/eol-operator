package notifier

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	helmv1alpha1 "github.com/asafd/eol-operator/api/v1alpha1"
	"github.com/asafd/eol-operator/internal/agent"
)

// TeamsNotifier posts alert notifications to a Microsoft Teams channel via a
// Power Automate HTTP trigger webhook.
//
// To create the webhook:
//  1. Go to flow.microsoft.com → New flow → Instant cloud flow
//  2. Trigger: "When a HTTP request is received" — paste the JSON schema from the README
//  3. Add step: "Post message in a chat or channel" → pick your team/channel
//  4. Save → copy the HTTP POST URL → set as TEAMS_WEBHOOK_URL env var
type TeamsNotifier struct {
	// webhookURL is the full Incoming Webhook URL from Teams.
	// Store it in a Kubernetes Secret and inject as TEAMS_WEBHOOK_URL env var.
	webhookURL string
	httpClient *http.Client
}

// NewTeamsNotifier constructs a TeamsNotifier for the given webhook URL.
func NewTeamsNotifier(webhookURL string) *TeamsNotifier {
	return &TeamsNotifier{
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// Name satisfies the Notifier interface. Returned value is appended to
// status.notificationsSent so the reconciler knows this channel was covered.
func (t *TeamsNotifier) Name() string { return "teams" }

// Send POSTs the alert data to the Power Automate HTTP trigger webhook.
// The payload is a flat JSON object matching the schema defined in the flow.
// Power Automate then formats and posts the message to the Teams channel.
func (t *TeamsNotifier) Send(ctx context.Context, alert *helmv1alpha1.HelmEOLAlert, report *agent.RiskReport) error {
	payload := t.buildPayload(alert, report)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshalling teams payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.webhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("posting to teams webhook: %w", err)
	}
	defer resp.Body.Close()

	// Power Automate HTTP triggers return 202 Accepted.
	// Old Office 365 Connectors returned 200 — accept both for compatibility.
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("teams webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// buildPayload constructs the flat JSON body sent to the Power Automate HTTP trigger.
// The schema here must match the "Request Body JSON Schema" defined in the flow.
// Power Automate extracts each field via triggerBody()?['fieldName'] expressions.
func (t *TeamsNotifier) buildPayload(alert *helmv1alpha1.HelmEOLAlert, report *agent.RiskReport) map[string]interface{} {
	breakingChanges := "None identified"
	if len(report.BreakingChanges) > 0 {
		breakingChanges = "• " + strings.Join(report.BreakingChanges, "\n• ")
	}
	cvesFixed := "None identified"
	if len(report.CVEsFixed) > 0 {
		cvesFixed = strings.Join(report.CVEsFixed, ", ")
	}

	return map[string]interface{}{
		"chartName":         alert.Spec.ChartName,
		"releaseName":       alert.Spec.ReleaseName,
		"namespace":         alert.Spec.Namespace,
		"installedVersion":  alert.Spec.InstalledVersion,
		"latestVersion":     alert.Spec.LatestVersion,
		"versionsBehind":    alert.Spec.VersionsBehind,
		"severity":          alert.Spec.Severity,
		"riskScore":         report.RiskScore,
		"upgradePath":       report.UpgradePath,
		"breakingChanges":   breakingChanges,
		"cvesFixed":         cvesFixed,
		"recommendedAction": report.RecommendedAction,
		"summary":           report.Summary,
	}
}
