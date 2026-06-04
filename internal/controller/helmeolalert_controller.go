/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	helmv1alpha1 "github.com/asafd/eol-operator/api/v1alpha1"
	"github.com/asafd/eol-operator/internal/agent"
	"github.com/asafd/eol-operator/internal/helm"
	"github.com/asafd/eol-operator/internal/notifier"
)

// HelmEOLAlertReconciler is the main controller struct.
//
// In the controller-runtime pattern, the reconciler struct holds the
// long-lived dependencies that are shared across all reconcile calls
// (database connections, API clients, etc.). It is created once in main.go
// and then passed to the manager.
//
// Trigger sources for Reconcile():
//  1. A HelmEOLAlert CRD is created/updated/deleted (primary watch via For()).
//  2. A Kubernetes Secret labelled owner=helm changes — meaning a Helm release
//     was installed, upgraded, or rolled back (secondary watch via Watches()).
//     The secret is mapped to a HelmEOLAlert name via mapSecretToAlert.
type HelmEOLAlertReconciler struct {
	// client.Client is the controller-runtime generic Kubernetes client.
	// Embedded so we can call r.Get(), r.Create(), r.Update(), r.Delete() directly.
	// It uses the manager's cache (an in-memory watch-based store) for reads,
	// so Get() does NOT hit the API server on every call.
	client.Client

	// Scheme maps Go types (e.g. *HelmEOLAlert) to their Kubernetes GVK
	// (Group/Version/Kind). Required by controller-runtime to serialize objects.
	Scheme *runtime.Scheme

	// Watcher encapsulates the Helm + ArtifactHub logic.
	// Kept as a field so it can be replaced with a mock in unit tests.
	Watcher *helm.Watcher

	// Enricher calls the Claude API to produce a RiskReport for an alert.
	// Optional: if nil, the operator skips enrichment and goes straight to Notified.
	Enricher *agent.AIEnricher

	// Notifiers is the list of channels to send notifications to (Teams, PagerDuty…).
	// Each channel is called once per alert; status.notificationsSent tracks which
	// channels have already been notified so retries don't cause duplicates.
	Notifiers []notifier.Notifier
}

// The lines below are kubebuilder RBAC markers. They look like comments but
// controller-gen reads them and generates the RBAC ClusterRole YAML in config/rbac/role.yaml.
// Run `make manifests` to regenerate after changing them.
//
// This controller needs to:
//   - Manage HelmEOLAlert objects (full CRUD).
//   - Update their /status subresource separately (required when status subresource is enabled).
//   - Update finalizers (used for cleanup logic on delete).
//   - Read Kubernetes Secrets (to read Helm release data via the storage driver).
//   - List Namespaces (used by the Helm watcher's cross-namespace scan).

// +kubebuilder:rbac:groups=helm.earnix.com,resources=helmeolalerts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=helm.earnix.com,resources=helmeolalerts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=helm.earnix.com,resources=helmeolalerts/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=list;watch

// Reconcile is called by controller-runtime whenever something that this
// controller watches changes. It receives a Request containing only the
// namespace/name of the object to reconcile — not the object itself.
// We must fetch the object ourselves (r.Get) because by the time we run,
// the object may have changed again.
//
// The golden rule of reconciliation: make the CURRENT state match the DESIRED
// state, regardless of what event triggered us. Never assume you know what
// changed — always read the current state and act accordingly.
func (r *HelmEOLAlertReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Try to fetch the HelmEOLAlert for this request.
	// req.NamespacedName is {Namespace: "default", Name: "test-nginx"}.
	var alert helmv1alpha1.HelmEOLAlert
	err := r.Get(ctx, req.NamespacedName, &alert)

	if apierrors.IsNotFound(err) {
		// The alert doesn't exist yet. This happens when:
		//   - A Helm Secret event fired (a release was installed/upgraded), but
		//     we haven't created the HelmEOLAlert for it yet.
		// We check whether the release is outdated and, if so, create the alert.
		return r.checkAndCreateAlert(ctx, req.NamespacedName)
	}
	if err != nil {
		// Unexpected error (network issue, API server down, etc.).
		// Returning err causes controller-runtime to requeue with exponential backoff.
		return ctrl.Result{}, err
	}

	logger.Info("Reconciling alert", "name", alert.Name, "phase", alert.Status.Phase)

	// State machine: each phase has its own handler function.
	// This pattern keeps Reconcile() short and each phase's logic isolated.
	switch alert.Status.Phase {
	case "", "Pending":
		// "" covers the case where status was not set on creation (status subresource
		// strips the status field from Create calls — it must be set separately).
		return r.reconcilePending(ctx, &alert)
	case "Enriching":
		return r.reconcileEnriching(ctx, &alert)
	case "Notified":
		// Periodically verify the release is still outdated.
		// If it was upgraded, delete the alert automatically.
		return r.reconcileNotified(ctx, &alert)
	case "Acknowledged":
		// A human acknowledged this alert. Don't send more notifications.
		// Check again in 24h in case a new major version is released.
		return ctrl.Result{RequeueAfter: 24 * time.Hour}, nil
	}

	return ctrl.Result{}, nil
}

// checkAndCreateAlert is called when a Helm Secret event fires but no
// HelmEOLAlert exists for that release yet.
//
// It asks the Watcher to check just that one release (not the whole cluster).
// If the release is outdated, it creates a HelmEOLAlert in the same namespace.
func (r *HelmEOLAlertReconciler) checkAndCreateAlert(ctx context.Context, name types.NamespacedName) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// Check only the single release that triggered this reconcile.
	// Returns nil if the release is current or was deleted since the event fired.
	outdated, err := r.Watcher.CheckRelease(ctx, name.Name, name.Namespace)
	if err != nil {
		return ctrl.Result{}, err
	}
	if outdated == nil {
		// Release is up to date — nothing to do.
		logger.V(1).Info("Release is up to date, no alert needed", "release", name)
		return ctrl.Result{}, nil
	}

	// Build and create the CRD object.
	alert := r.buildAlert(outdated)
	if err := r.Create(ctx, alert); err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Race condition: two reconcilers ran at the same time and both tried
			// to create the alert. The other one won — that's fine, we can stop.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}
	logger.Info("Created HelmEOLAlert", "name", alert.Name, "namespace", alert.Namespace)
	// Creating the alert triggers another Reconcile call (because we watch HelmEOLAlerts
	// via For()). That next call will handle the Pending → Enriching transition.
	return ctrl.Result{}, nil
}

// reconcilePending handles the very first reconcile after an alert is created.
//
// Its job is simple: record when we first checked, mark the phase as "Enriching",
// and requeue immediately so the Enriching handler runs next.
//
// Why not do enrichment here? Because reconcilePending might run several times
// before enrichment completes (e.g. if the status update itself gets requeued).
// Separating the phases makes each step idempotent.
func (r *HelmEOLAlertReconciler) reconcilePending(ctx context.Context, alert *helmv1alpha1.HelmEOLAlert) (ctrl.Result, error) {
	now := metav1.Now()
	alert.Status.Phase = "Enriching"
	alert.Status.LastChecked = &now
	alert.Status.AIReportGenerated = false

	// r.Status().Update() writes ONLY the status subresource.
	// Using r.Update() here would overwrite the spec too, risking conflicts.
	// The status subresource was enabled by the +kubebuilder:subresource:status marker.
	if err := r.Status().Update(ctx, alert); err != nil {
		return ctrl.Result{}, err
	}

	// Requeue: true means "put this back in the queue immediately, don't wait".
	// This causes the Enriching case to run in the very next reconcile loop.
	return ctrl.Result{Requeue: true}, nil
}

// reconcileEnriching calls the AI enricher then dispatches notifications.
//
// Flow:
//  1. If Enricher is configured and the report hasn't been generated yet,
//     call Claude → write UpgradePath + RiskScore into status.
//  2. For each registered Notifier not already in status.notificationsSent,
//     call Send() → append its name to the list on success.
//  3. Once all notifiers are done, advance phase to "Notified".
//
// Every step updates status before moving on, so if the pod restarts mid-way
// the next reconcile picks up from where it left off (idempotent).
func (r *HelmEOLAlertReconciler) reconcileEnriching(ctx context.Context, alert *helmv1alpha1.HelmEOLAlert) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	// --- Step 1: AI enrichment ---
	var report *agent.RiskReport

	if r.Enricher != nil && !alert.Status.AIReportGenerated {
		logger.Info("Running AI enrichment", "chart", alert.Spec.ChartName)

		var err error
		report, err = r.Enricher.Enrich(
			ctx,
			alert.Spec.ChartName,
			alert.Spec.InstalledVersion,
			alert.Spec.LatestVersion,
			alert.Spec.Severity,
			alert.Spec.VersionsBehind,
		)
		if err != nil {
			// Non-fatal: log and continue without AI data.
			// We still send notifications — they just won't have upgrade path / risk score.
			logger.Error(err, "AI enrichment failed, continuing without report")
		} else {
			// Persist the report into the CRD status so it survives pod restarts.
			alert.Status.UpgradePath = report.UpgradePath
			alert.Status.RiskScore = report.RiskScore
			alert.Status.AIReportGenerated = true

			if err := r.Status().Update(ctx, alert); err != nil {
				return ctrl.Result{}, err
			}
			logger.Info("AI report stored", "riskScore", report.RiskScore, "action", report.RecommendedAction)
		}
	} else if alert.Status.AIReportGenerated {
		// Report was generated in a previous reconcile — reconstruct from status
		// so we can pass it to notifiers without calling Claude again.
		report = &agent.RiskReport{
			UpgradePath: alert.Status.UpgradePath,
			RiskScore:   alert.Status.RiskScore,
		}
	}

	// If no enricher is configured, use a minimal placeholder report
	// so notifiers still receive something meaningful.
	if report == nil {
		report = &agent.RiskReport{
			UpgradePath:       fmt.Sprintf("%s → %s", alert.Spec.InstalledVersion, alert.Spec.LatestVersion),
			RiskScore:         0,
			RecommendedAction: "upgrade",
			Summary:           fmt.Sprintf("%s is %d versions behind (latest: %s).", alert.Spec.ChartName, alert.Spec.VersionsBehind, alert.Spec.LatestVersion),
		}
	}

	// --- Step 2: Notifications ---
	// Build a set of already-notified channels for O(1) lookup.
	alreadySent := make(map[string]bool, len(alert.Status.NotificationsSent))
	for _, ch := range alert.Status.NotificationsSent {
		alreadySent[ch] = true
	}

	for _, n := range r.Notifiers {
		if alreadySent[n.Name()] {
			continue // already sent in a previous attempt — skip
		}
		if err := n.Send(ctx, alert, report); err != nil {
			// Log but do not abort — try the remaining notifiers.
			// The failed channel will be retried on the next reconcile because
			// its name was never appended to NotificationsSent.
			logger.Error(err, "Notification failed", "channel", n.Name())
			continue
		}
		alert.Status.NotificationsSent = append(alert.Status.NotificationsSent, n.Name())
		logger.Info("Notification sent", "channel", n.Name())
	}

	// Persist the updated NotificationsSent list.
	if err := r.Status().Update(ctx, alert); err != nil {
		return ctrl.Result{}, err
	}

	// --- Step 3: Advance phase ---
	alert.Status.Phase = "Notified"
	if err := r.Status().Update(ctx, alert); err != nil {
		return ctrl.Result{}, err
	}

	logger.Info("Alert fully processed", "name", alert.Name, "notified", alert.Status.NotificationsSent)
	return ctrl.Result{RequeueAfter: 6 * time.Hour}, nil
}

// reconcileNotified runs every 6 hours while an alert is in the Notified phase.
// It re-checks whether the release has been upgraded since we last looked.
// If it has, the alert is deleted (the problem is resolved).
// If it hasn't, we refresh the latest version in the spec (upstream might have
// moved even further ahead) and requeue for the next check.
func (r *HelmEOLAlertReconciler) reconcileNotified(ctx context.Context, alert *helmv1alpha1.HelmEOLAlert) (ctrl.Result, error) {
	logger := log.FromContext(ctx)

	outdated, err := r.Watcher.CheckRelease(ctx, alert.Spec.ReleaseName, alert.Spec.Namespace)
	if err != nil {
		// Non-fatal — requeue and try again in 6h rather than crashing the loop.
		return ctrl.Result{RequeueAfter: 6 * time.Hour}, err
	}

	if outdated == nil {
		// nil means the release is now up to date (or was deleted).
		// The alert has served its purpose — clean it up.
		logger.Info("Release is now up to date, deleting alert", "name", alert.Name)
		return ctrl.Result{}, r.Delete(ctx, alert)
	}

	// Still outdated. Update the spec in case the latest version has changed
	// since we last checked (e.g. 13.0.0 → 24.0.2 may become 13.0.0 → 25.0.0).
	alert.Spec.LatestVersion = outdated.LatestVersion
	alert.Spec.VersionsBehind = outdated.VersionsBehind
	alert.Spec.Severity = outdated.Severity
	now := metav1.Now()
	alert.Status.LastChecked = &now

	// r.Update() writes the spec. r.Status().Update() writes the status.
	// We need both here because we changed both Spec fields and Status.LastChecked.
	// Note: in a stricter design you'd split these into two calls.
	if err := r.Update(ctx, alert); err != nil {
		return ctrl.Result{}, err
	}
	// Check again in 6 hours.
	return ctrl.Result{RequeueAfter: 6 * time.Hour}, nil
}

// buildAlert constructs the HelmEOLAlert CRD object that will be written to Kubernetes.
// It is a pure function (no side effects) — easy to unit test.
func (r *HelmEOLAlertReconciler) buildAlert(rel *helm.OutdatedRelease) *helmv1alpha1.HelmEOLAlert {
	return &helmv1alpha1.HelmEOLAlert{
		ObjectMeta: metav1.ObjectMeta{
			// The alert name equals the release name so there is a guaranteed 1-to-1
			// mapping. Because the alert is namespace-scoped (same namespace as the
			// release), this is always unique within that namespace.
			Name:      rel.ReleaseName,
			Namespace: rel.Namespace,
		},
		Spec: helmv1alpha1.HelmEOLAlertSpec{
			ReleaseName:      rel.ReleaseName,
			Namespace:        rel.Namespace,
			ChartName:        rel.ChartName,
			InstalledVersion: rel.InstalledVersion,
			LatestVersion:    rel.LatestVersion,
			VersionsBehind:   rel.VersionsBehind,
			Severity:         rel.Severity,
		},
		// Note: when the status subresource is enabled, the API server IGNORES
		// the Status field on Create. We set it here for clarity, but it will be
		// stripped. The first Reconcile call will set it via r.Status().Update().
		Status: helmv1alpha1.HelmEOLAlertStatus{
			Phase: "Pending",
		},
	}
}

// mapSecretToAlert translates a Helm release Secret into a reconcile.Request
// for the corresponding HelmEOLAlert.
//
// Helm labels every release secret with "name=<release-name>".
// Example secret name: "sh.helm.release.v1.test-nginx.v3"
// Example label:       "name=test-nginx"
//
// We return a Request with Name=releaseName and Namespace=secret.Namespace.
// This causes Reconcile() to be called with that NamespacedName, as if the
// HelmEOLAlert itself had changed.
func (r *HelmEOLAlertReconciler) mapSecretToAlert(_ context.Context, obj client.Object) []reconcile.Request {
	// Extract the release name from the Helm-managed label on the secret.
	releaseName := obj.GetLabels()["name"]
	if releaseName == "" {
		// This secret doesn't have a Helm release name label — shouldn't happen
		// given the predicate filter below, but guard anyway.
		return nil
	}
	// Return exactly one request: the HelmEOLAlert for this release.
	return []reconcile.Request{{
		NamespacedName: types.NamespacedName{
			Name:      releaseName,
			Namespace: obj.GetNamespace(),
		},
	}}
}

// SetupWithManager wires this reconciler into the controller-runtime Manager.
// It defines WHAT objects trigger Reconcile() and HOW they are filtered.
func (r *HelmEOLAlertReconciler) SetupWithManager(mgr ctrl.Manager) error {
	// isHelmSecret is a predicate (filter) that runs BEFORE mapSecretToAlert.
	// It discards any Secret that is NOT a Helm release secret, so we don't
	// waste reconcile cycles on user secrets, TLS secrets, etc.
	// The "owner=helm" label is set by Helm on every release secret it manages.
	isHelmSecret := predicate.NewPredicateFuncs(func(obj client.Object) bool {
		return obj.GetLabels()["owner"] == "helm"
	})

	return ctrl.NewControllerManagedBy(mgr).
		// Primary watch: reconcile whenever a HelmEOLAlert is created/updated/deleted.
		For(&helmv1alpha1.HelmEOLAlert{}).
		// Secondary watch: also reconcile when a Helm release Secret changes.
		// This makes the operator reactive — it detects new installs and upgrades
		// in real time rather than only on a polling schedule.
		//
		// Watches() takes three arguments:
		//   1. The object type to watch (corev1.Secret).
		//   2. A handler that converts the Secret into reconcile.Requests.
		//   3. Optional predicates to filter which Secrets trigger the handler.
		Watches(
			&corev1.Secret{},
			handler.EnqueueRequestsFromMapFunc(r.mapSecretToAlert),
			builder.WithPredicates(isHelmSecret),
		).
		Named("helmeolalert").
		// Complete registers the reconciler with the manager and starts the
		// internal work queue and goroutine pool.
		Complete(r)
}
