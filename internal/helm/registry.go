package helm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RegistryClient resolves the latest published version of a Helm chart by
// querying ArtifactHub — the central index for public Helm charts (think of it
// as "npm registry but for Helm"). It covers bitnami, ingress-nginx, cert-manager,
// and thousands of other well-known charts.
//
// Limitation: private / internal charts that are not published to ArtifactHub
// will not be found. See the TODO in GetLatestVersion for the extension point.
type RegistryClient struct {
	// httpClient is reused across requests to benefit from connection pooling.
	// The 10s timeout prevents a slow ArtifactHub response from blocking a reconcile.
	httpClient *http.Client
}

// NewRegistryClient returns a ready-to-use RegistryClient.
func NewRegistryClient() *RegistryClient {
	return &RegistryClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// GetLatestVersion returns the newest non-prerelease version string for a chart.
//
// Resolution order (fast path first):
//  1. Some chart maintainers annotate their Chart.yaml Sources list with an
//     ArtifactHub URL. If we find one, we do a direct REST call — O(1), exact.
//  2. Otherwise we fall back to a full-text search on ArtifactHub by chart name.
//
// TODO: Add a third resolver that fetches a private Helm repo's index.yaml
// (configured via the EOLOperatorConfig CRD) so internal charts are also covered.
func (c *RegistryClient) GetLatestVersion(ctx context.Context, chartName string, sources []string) (string, error) {
	// sources is the list of URLs from Chart.yaml's "sources:" field.
	// Most charts put their GitHub repo here, but some also include the ArtifactHub URL.
	for _, src := range sources {
		if version, err := c.fetchFromArtifactHubURL(ctx, src); err == nil {
			// Found a direct ArtifactHub URL — use it and return immediately.
			return version, nil
		}
		// err != nil just means this source URL is not an ArtifactHub one — keep trying.
	}

	// None of the source URLs were ArtifactHub links; fall back to search.
	return c.searchArtifactHub(ctx, chartName)
}

// artifactHubPackage is a minimal Go representation of the JSON object that
// ArtifactHub returns for a single chart package. We only need Name and Version;
// the real response has many more fields which we discard via JSON decoding.
type artifactHubPackage struct {
	Version string `json:"version"`
	Name    string `json:"name"`
}

// artifactHubSearchResponse is the top-level JSON shape of the search endpoint.
// ArtifactHub returns a "packages" array of results ordered by relevance.
type artifactHubSearchResponse struct {
	Packages []artifactHubPackage `json:"packages"`
}

// searchArtifactHub hits the ArtifactHub search API and returns the latest version
// for the best-matching chart.
//
// URL breakdown:
//
//	kind=0             → Helm charts only (kind 1 = OPA policies, 2 = OLM, etc.)
//	ts_query_web=<name>→ full-text search term (URL-encoded)
//	limit=10           → fetch up to 10 results so we can find an exact name match
//	sort=relevance     → highest-confidence match comes first
func (c *RegistryClient) searchArtifactHub(ctx context.Context, chartName string) (string, error) {
	endpoint := fmt.Sprintf(
		"https://artifacthub.io/api/v1/packages/search?kind=0&ts_query_web=%s&limit=10&sort=relevance",
		url.QueryEscape(chartName), // QueryEscape turns "cert manager" → "cert+manager", preventing HTTP errors
	)

	// NewRequestWithContext attaches the controller's context to the HTTP request.
	// If the reconciler times out or is cancelled, the HTTP call is cancelled too —
	// no goroutine leak.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", err
	}
	// ArtifactHub returns JSON by default, but being explicit is good practice.
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("artifacthub search %q: %w", chartName, err)
	}
	// defer closes the body when this function returns, even on error paths.
	// Forgetting this would leak the TCP connection.
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifacthub search %q: HTTP %d", chartName, resp.StatusCode)
	}

	// Stream-decode the JSON body directly into our struct without loading it
	// all into memory first. Efficient for large responses.
	var result artifactHubSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decoding artifacthub response: %w", err)
	}

	// ArtifactHub search is fuzzy — searching for "nginx" might return "nginx-ingress"
	// first. We prefer an exact name match over the top-ranked fuzzy result.
	for _, pkg := range result.Packages {
		if pkg.Name == chartName {
			return pkg.Version, nil
		}
	}
	// No exact match — take whatever ranked highest. This handles charts whose
	// ArtifactHub name differs slightly from their chart name.
	if len(result.Packages) > 0 {
		return result.Packages[0].Version, nil
	}
	return "", fmt.Errorf("chart %q not found on artifacthub", chartName)
}

// fetchFromArtifactHubURL checks whether src is an ArtifactHub package URL and,
// if so, calls the ArtifactHub REST API directly for that exact package.
//
// ArtifactHub package URLs look like:
//
//	https://artifacthub.io/packages/helm/bitnami/nginx
//
// The corresponding API endpoint is:
//
//	https://artifacthub.io/api/v1/packages/helm/bitnami/nginx
//
// We simply swap the path prefix from "/packages/" to "/api/v1/packages/".
func (c *RegistryClient) fetchFromArtifactHubURL(ctx context.Context, src string) (string, error) {
	const ahPrefix = "https://artifacthub.io/packages/helm/"

	// If the source URL is not an ArtifactHub URL at all, return an error so
	// the caller knows to try the next source or fall back to search.
	if !strings.HasPrefix(src, ahPrefix) {
		return "", fmt.Errorf("not an artifacthub URL")
	}

	// Strip the browser-facing prefix and build the API URL.
	// e.g. "bitnami/nginx" → "https://artifacthub.io/api/v1/packages/helm/bitnami/nginx"
	path := strings.TrimPrefix(src, "https://artifacthub.io/packages/helm/")
	apiURL := "https://artifacthub.io/api/v1/packages/helm/" + path

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("artifacthub direct lookup %q: %w", src, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifacthub direct lookup %q: HTTP %d", src, resp.StatusCode)
	}

	// The single-package endpoint returns one artifactHubPackage object directly
	// (not wrapped in a "packages" array like the search endpoint).
	var pkg artifactHubPackage
	if err := json.NewDecoder(resp.Body).Decode(&pkg); err != nil {
		return "", fmt.Errorf("decoding artifacthub package: %w", err)
	}
	return pkg.Version, nil
}
