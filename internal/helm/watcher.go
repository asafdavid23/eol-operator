// Package helm provides utilities for discovering outdated Helm releases
// installed in a Kubernetes cluster.
//
// # How Helm stores releases
//
// Helm v3 does NOT have its own database. Instead, it stores each release
// revision as a Kubernetes Secret in the same namespace as the release.
// The secret is labelled:
//
//	owner=helm          ← marks it as a Helm-managed secret (not a user secret)
//	name=<release>      ← the Helm release name you gave at `helm install`
//	status=deployed     ← current active revision (others are "superseded")
//
// The Secret's data["release"] key holds a base64-encoded, gzip-compressed
// JSON blob of the full release object (chart metadata, values, manifest, etc.).
//
// This package reads those Secrets via the typed k8s.io/client-go client and
// uses the helm.sh/helm/v3/pkg/storage/driver package to decode them into
// typed Go structs — no kubectl, no kubeconfig file, no Helm CLI needed.
package helm

import (
	"context"
	"fmt"

	// rspb is the Helm "release" package — rspb stands for "release spec pb (protobuf)".
	// It defines the Release struct that contains Chart, Config, Manifest, Info, etc.
	rspb "helm.sh/helm/v3/pkg/release"

	// storage provides the high-level Store abstraction (ListDeployed, Query, etc.)
	// that sits on top of the raw driver.
	"helm.sh/helm/v3/pkg/storage"

	// driver contains the Secrets backend — it knows how to read/write Helm release
	// data from/to Kubernetes Secrets, including the base64+gzip decoding.
	"helm.sh/helm/v3/pkg/storage/driver"

	// kubernetes is the typed k8s client. "typed" means each API group has its own
	// Go interface (e.g. CoreV1().Secrets()) rather than working with raw JSON.
	"k8s.io/client-go/kubernetes"

	// rest.Config carries the cluster URL, TLS certs, and auth token.
	// When running in-cluster, mgr.GetConfig() returns an in-cluster config
	// that reads the service account token from /var/run/secrets/.
	"k8s.io/client-go/rest"

	// controller-runtime's structured logger. log.FromContext extracts the logger
	// that the reconciler attached to the context, which includes reconcile metadata
	// (name, namespace, reconcileID) automatically.
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// OutdatedRelease is a plain data struct — no Kubernetes machinery attached.
// The watcher produces these; the controller consumes them to create HelmEOLAlert CRDs.
// Keeping it as a plain struct (not a CRD type) makes the watcher testable in
// isolation without a real cluster.
type OutdatedRelease struct {
	// ReleaseName is the Helm release name (e.g. "nginx").
	ReleaseName string
	// Namespace is the Kubernetes namespace the release is installed in.
	Namespace string
	// ChartName is the chart identifier (e.g. "nginx", "cert-manager").
	ChartName string
	// InstalledVersion is the semver string currently running in the cluster.
	InstalledVersion string
	// LatestVersion is the latest non-prerelease version found in the registry.
	LatestVersion string
	// VersionsBehind is the number of minor or major versions the release lags.
	VersionsBehind int
	// Severity is one of "minor", "major", or "eol".
	Severity string
}

// Watcher reads Helm release data directly from cluster Secrets and identifies
// charts that are behind the latest published version.
// It is created once at operator start-up (NewWatcher) and reused across reconciles.
type Watcher struct {
	// k8sClient is the typed Kubernetes client used to read Secrets.
	// We use the typed client (not controller-runtime's generic client) because
	// the Helm storage driver expects a typed corev1.SecretInterface.
	k8sClient *kubernetes.Clientset

	// registryClient handles the outbound HTTP calls to ArtifactHub.
	registryClient *RegistryClient
}

// NewWatcher constructs a Watcher from a REST config.
// The REST config comes from mgr.GetConfig() in main.go — when running in-cluster
// this is automatically populated from the pod's service account token.
func NewWatcher(cfg *rest.Config) (*Watcher, error) {
	// kubernetes.NewForConfig builds a typed client using the provided config.
	// It creates one HTTP client per API group internally and reuses connections.
	k8sClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client for helm watcher: %w", err)
	}
	return &Watcher{
		k8sClient:      k8sClient,
		registryClient: NewRegistryClient(),
	}, nil
}

// ListOutdatedReleases is the full-cluster scan path.
// It lists every deployed release across all namespaces, checks each one against
// ArtifactHub, and returns those that are behind the latest version.
//
// Called by: (future) startup scan and periodic poll.
// NOT called on every Helm Secret event — use CheckRelease for that.
//
// Charts that cannot be resolved (private registries, network errors) are
// logged at V(1) and skipped — the scan continues for all others.
func (w *Watcher) ListOutdatedReleases(ctx context.Context) ([]OutdatedRelease, error) {
	logger := log.FromContext(ctx)

	releases, err := w.listDeployedReleases()
	if err != nil {
		return nil, fmt.Errorf("listing helm releases from cluster: %w", err)
	}
	logger.Info("Helm scan: found deployed releases", "total", len(releases))

	var outdated []OutdatedRelease
	for _, rel := range releases {
		// Guard against corrupt or partially-decoded release objects.
		if rel.Chart == nil || rel.Chart.Metadata == nil {
			continue
		}

		chartName := rel.Chart.Name() // reads Chart.Metadata.Name
		installedVersion := rel.Chart.Metadata.Version
		sources := rel.Chart.Metadata.Sources // e.g. ["https://github.com/bitnami/charts"]

		latest, err := w.registryClient.GetLatestVersion(ctx, chartName, sources)
		if err != nil {
			// Not a fatal error — just means we can't check this chart right now.
			// V(1) = debug level, won't appear in default log output.
			logger.V(1).Info("Skipping chart — could not resolve latest version",
				"release", rel.Name, "chart", chartName, "error", err)
			continue
		}

		// isOutdated does a semver LT comparison. Returns false if already current.
		if !isOutdated(installedVersion, latest) {
			continue
		}

		behind, severity := classifyGap(installedVersion, latest)
		outdated = append(outdated, OutdatedRelease{
			ReleaseName:      rel.Name,
			Namespace:        rel.Namespace,
			ChartName:        chartName,
			InstalledVersion: installedVersion,
			LatestVersion:    latest,
			VersionsBehind:   behind,
			Severity:         severity,
		})
		logger.Info("Outdated release found",
			"release", rel.Name,
			"namespace", rel.Namespace,
			"installed", installedVersion,
			"latest", latest,
			"severity", severity,
		)
	}

	logger.Info("Helm scan complete", "outdated", len(outdated))
	return outdated, nil
}

// CheckRelease is the targeted, single-release check path.
// It is called by the reconciler when a Helm Secret event fires (a release was
// installed or upgraded), to avoid scanning the entire cluster just for one event.
//
// Returns:
//   - (*OutdatedRelease, nil) if the release is outdated
//   - (nil, nil)              if the release is current (no alert needed) or not found
//   - (nil, err)              if something went wrong (will be requeued)
func (w *Watcher) CheckRelease(ctx context.Context, releaseName, namespace string) (*OutdatedRelease, error) {
	// We still call listDeployedReleases (reads all secrets) because the Helm
	// storage driver doesn't support fetching a single release by name+namespace
	// without reading all secrets first. This is acceptable — secrets are small
	// and Kubernetes API server responses are cached by the client.
	releases, err := w.listDeployedReleases()
	if err != nil {
		return nil, err
	}

	for _, rel := range releases {
		// Skip releases that don't match the one we're looking for.
		if rel.Name != releaseName || rel.Namespace != namespace {
			continue
		}
		if rel.Chart == nil || rel.Chart.Metadata == nil {
			return nil, nil // release exists but has no chart data — treat as not found
		}

		installedVersion := rel.Chart.Metadata.Version
		latest, err := w.registryClient.GetLatestVersion(ctx, rel.Chart.Name(), rel.Chart.Metadata.Sources)
		if err != nil {
			// Wrap the error with context so the caller's log is informative.
			return nil, fmt.Errorf("resolving latest version for %s/%s: %w", namespace, releaseName, err)
		}
		if !isOutdated(installedVersion, latest) {
			return nil, nil // up to date — no alert needed
		}

		behind, severity := classifyGap(installedVersion, latest)
		return &OutdatedRelease{
			ReleaseName:      releaseName,
			Namespace:        namespace,
			ChartName:        rel.Chart.Name(),
			InstalledVersion: installedVersion,
			LatestVersion:    latest,
			VersionsBehind:   behind,
			Severity:         severity,
		}, nil
	}

	// Release was not found in the deployed list — it may have been deleted
	// between when the Secret event fired and when we got here.
	return nil, nil
}

// listDeployedReleases is the low-level function that actually reads from the cluster.
//
// How it works, step by step:
//  1. w.k8sClient.CoreV1().Secrets("") returns a SecretInterface scoped to ALL
//     namespaces (passing "" means "no namespace filter").
//  2. driver.NewSecrets wraps that SecretInterface. When you call its List method,
//     it queries Kubernetes for Secrets with label "owner=helm" and then decodes
//     the base64+gzip+JSON data["release"] field into a *release.Release struct.
//  3. storage.Init wraps the driver in a higher-level Store that provides
//     convenience methods like ListDeployed (which filters to status=deployed).
//  4. store.ListDeployed() calls driver.List with a filter function that checks
//     rel.Info.Status.IsDeploy() — only returns the currently active revision,
//     not superseded or failed ones.
func (w *Watcher) listDeployedReleases() ([]*rspb.Release, error) {
	// "" namespace = list across all namespaces.
	// Requires the RBAC marker: // +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch
	secretsClient := w.k8sClient.CoreV1().Secrets("")

	// The Helm driver reads secrets and decodes the Helm release from each one.
	d := driver.NewSecrets(secretsClient)

	// The storage layer adds filtering and querying on top of the raw driver.
	store := storage.Init(d)

	// ListDeployed returns only releases with status=deployed (not superseded/failed).
	return store.ListDeployed()
}
