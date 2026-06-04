// Package notifier defines the interface for sending EOL alert notifications
// and provides concrete implementations for Microsoft Teams and PagerDuty.
package notifier

import (
	"context"

	helmv1alpha1 "github.com/asafd/eol-operator/api/v1alpha1"
	"github.com/asafd/eol-operator/internal/agent"
)

// Notifier is the interface every notification channel must implement.
// The reconciler holds a []Notifier and iterates over them, so adding a new
// channel (Slack, email, Jira ticket) only requires implementing this interface
// and registering it in main.go — no changes to the controller logic needed.
type Notifier interface {
	// Send delivers the alert and its AI-generated risk report to the channel.
	// It must be idempotent: if the same alert is sent twice, the second call
	// should not create a duplicate notification (use dedup keys where possible).
	Send(ctx context.Context, alert *helmv1alpha1.HelmEOLAlert, report *agent.RiskReport) error

	// Name returns the short channel identifier, e.g. "teams" or "pagerduty".
	// The reconciler appends this to status.notificationsSent after a successful
	// Send(), so it knows which channels still need to be called on retry.
	Name() string
}

// severityColour maps the alert severity to a hex colour for visual formatting.
// Used by the Teams Adaptive Card to colour the header bar.
func severityColour(severity string) string {
	switch severity {
	case "eol":
		return "attention" // red in Teams Adaptive Cards
	case "major":
		return "warning" // orange
	default:
		return "accent" // blue (minor)
	}
}

// pdSeverity maps our internal severity + risk score to a PagerDuty severity string.
// PagerDuty accepts: "critical", "error", "warning", "info".
func pdSeverity(severity string, riskScore int) string {
	// High risk score overrides the version-gap severity.
	if riskScore >= 8 {
		return "critical"
	}
	switch severity {
	case "eol":
		return "critical"
	case "major":
		return "error"
	default:
		return "warning"
	}
}
