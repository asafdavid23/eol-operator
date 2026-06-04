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

const pdEventsEndpoint = "https://events.pagerduty.com/v2/enqueue"

// PagerDutyNotifier fires an incident via the PagerDuty Events API v2.
// It uses a dedup_key derived from the release name + namespace so that
// repeated calls for the same alert update the existing incident rather
// than creating a new one.
//
// To get a routing key:
//
//	PagerDuty → Services → <your service> → Integrations → Add → Events API v2
type PagerDutyNotifier struct {
	// routingKey is the 32-character integration key from the PagerDuty service.
	// Store it in a Kubernetes Secret and inject as PD_ROUTING_KEY env var.
	routingKey string

	// minSeverity controls the minimum alert severity that triggers a page.
	// "minor" = page on everything, "major" = skip minor, "eol" = only page on eol.
	// Defaults to "major" so minor patch gaps don't wake someone at 3am.
	minSeverity string

	httpClient *http.Client
}

// NewPagerDutyNotifier constructs a PagerDutyNotifier.
// minSeverity should be one of "minor", "major", "eol". Pass "major" if unsure.
func NewPagerDutyNotifier(routingKey, minSeverity string) *PagerDutyNotifier {
	if minSeverity == "" {
		minSeverity = "major"
	}
	return &PagerDutyNotifier{
		routingKey:  routingKey,
		minSeverity: minSeverity,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

// Name satisfies the Notifier interface.
func (p *PagerDutyNotifier) Name() string { return "pagerduty" }

// Send fires a PagerDuty event for the alert.
// If the alert severity is below minSeverity, Send is a no-op (returns nil).
// This avoids flooding on-call with minor patch notifications.
func (p *PagerDutyNotifier) Send(ctx context.Context, alert *helmv1alpha1.HelmEOLAlert, report *agent.RiskReport) error {
	if !p.shouldPage(alert.Spec.Severity) {
		return nil // below threshold — skip silently
	}

	event := p.buildEvent(alert, report)

	body, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshalling pagerduty event: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, pdEventsEndpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("posting to pagerduty: %w", err)
	}
	defer resp.Body.Close()

	// PagerDuty returns 202 Accepted on success (event is queued, not yet processed).
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("pagerduty returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// pdEvent is the full PagerDuty Events API v2 payload.
// Using a typed struct (rather than map[string]interface{}) so the JSON
// field names and types are validated at compile time.
type pdEvent struct {
	RoutingKey  string    `json:"routing_key"`
	EventAction string    `json:"event_action"` // "trigger" | "acknowledge" | "resolve"
	DedupKey    string    `json:"dedup_key"`    // prevents duplicate incidents on retry
	Payload     pdPayload `json:"payload"`
}

type pdPayload struct {
	Summary       string                 `json:"summary"`
	Severity      string                 `json:"severity"` // "critical"|"error"|"warning"|"info"
	Source        string                 `json:"source"`
	CustomDetails map[string]interface{} `json:"custom_details"`
}

// buildEvent constructs the PagerDuty event payload.
func (p *PagerDutyNotifier) buildEvent(alert *helmv1alpha1.HelmEOLAlert, report *agent.RiskReport) pdEvent {
	// dedup_key is stable across retries: same release = same key = same PD incident.
	// PagerDuty deduplicates on this key, so a second trigger call updates the
	// existing incident rather than creating a new one.
	dedupKey := fmt.Sprintf("eol-operator/%s/%s", alert.Spec.Namespace, alert.Spec.ReleaseName)

	summary := fmt.Sprintf(
		"[Helm EOL] %s/%s: %s installed, latest is %s (%s, %d versions behind, risk %d/10)",
		alert.Spec.Namespace,
		alert.Spec.ReleaseName,
		alert.Spec.InstalledVersion,
		alert.Spec.LatestVersion,
		alert.Spec.Severity,
		alert.Spec.VersionsBehind,
		report.RiskScore,
	)

	return pdEvent{
		RoutingKey:  p.routingKey,
		EventAction: "trigger",
		DedupKey:    dedupKey,
		Payload: pdPayload{
			Summary:  summary,
			Severity: pdSeverity(alert.Spec.Severity, report.RiskScore), // defined in notifier.go
			Source:   "eol-operator",
			CustomDetails: map[string]interface{}{
				"chart":            alert.Spec.ChartName,
				"release":          alert.Spec.ReleaseName,
				"namespace":        alert.Spec.Namespace,
				"installed":        alert.Spec.InstalledVersion,
				"latest":           alert.Spec.LatestVersion,
				"upgrade_path":     report.UpgradePath,
				"risk_score":       report.RiskScore,
				"recommended":      report.RecommendedAction,
				"breaking_changes": strings.Join(report.BreakingChanges, "; "),
				"cves_fixed":       strings.Join(report.CVEsFixed, ", "),
				"summary":          report.Summary,
			},
		},
	}
}

// shouldPage returns true if the alert severity is at or above the configured
// minimum severity. Severity order: minor < major < eol.
func (p *PagerDutyNotifier) shouldPage(severity string) bool {
	order := map[string]int{
		"minor": 1,
		"major": 2,
		"eol":   3,
	}
	return order[severity] >= order[p.minSeverity]
}
