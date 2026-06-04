package helm

import (
	"fmt"

	// semver is aliased to avoid the verbose package name "semver/v4".
	// github.com/blang/semver/v4 was already an indirect dependency in go.mod
	// (pulled in by controller-runtime), so we didn't need to add it explicitly.
	semver "github.com/blang/semver/v4"
)

// isOutdated reports whether the installed version is strictly older than latest.
//
// We use ParseTolerant instead of Parse because real-world Helm chart versions
// are often not strictly valid semver — e.g. "13.0.0" is fine, but some charts
// ship versions like "v1.2.3" (with a leading "v") or "1.2.3-chart" which
// strict Parse would reject. ParseTolerant strips the "v" prefix and other
// common deviations before parsing.
//
// Returns false (treat as up-to-date) if either string cannot be parsed at all,
// so a broken chart version never causes a crash.
func isOutdated(installed, latest string) bool {
	iv, err := semver.ParseTolerant(installed)
	if err != nil {
		// Cannot parse the installed version — skip rather than panic.
		return false
	}
	lv, err := semver.ParseTolerant(latest)
	if err != nil {
		// Cannot parse the registry version — skip rather than panic.
		return false
	}
	// iv.LT(lv) is true when installed < latest (strictly behind).
	// Equal versions (iv == lv) correctly return false.
	return iv.LT(lv)
}

// classifyGap returns two things:
//  1. How many major or minor versions the release is behind (integer).
//  2. A severity label string: "minor", "major", or "eol".
//
// The severity drives two decisions downstream:
//   - Which PagerDuty urgency level to use (critical vs warning).
//   - The colour of the Teams Adaptive Card (red / orange / yellow).
//
// Returns (0, "unknown") if either version string cannot be parsed.
func classifyGap(installed, latest string) (int, string) {
	iv, err := semver.ParseTolerant(installed)
	if err != nil {
		return 0, "unknown"
	}
	lv, err := semver.ParseTolerant(latest)
	if err != nil {
		return 0, "unknown"
	}

	// Check for a major version gap first because a jump from 1.x → 3.x is
	// far more severe than a jump from 1.0 → 1.5.
	if lv.Major > iv.Major {
		majorsBehind := int(lv.Major - iv.Major)
		// Two or more major versions = "end of life" territory.
		// The installed version is unlikely to receive backported security patches.
		if majorsBehind >= 2 {
			return majorsBehind, "eol"
		}
		// One major version behind — breaking changes are likely but the chart
		// is not completely abandoned.
		return majorsBehind, "major"
	}

	// Same major version — count minor increments.
	// Patch-only bumps are included here (reported as 0 minor versions behind
	// but still flagged by isOutdated via the LT comparison).
	minorsBehind := int(lv.Minor - iv.Minor)
	return minorsBehind, "minor"
}

// AlertName produces a deterministic, DNS-label-safe name for a HelmEOLAlert CRD.
// Kubernetes resource names must be unique within a namespace. Because the alert
// lives in the same namespace as the release, using just the release name is
// sufficient — but if you ever make alerts cluster-scoped, prepending the
// namespace prevents collisions across namespaces.
//
// Example: releaseName="nginx", namespace="prod" → "prod-nginx"
func AlertName(releaseName, namespace string) string {
	return fmt.Sprintf("%s-%s", namespace, releaseName)
}
