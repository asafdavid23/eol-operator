# eol-operator

A Kubernetes operator that detects outdated Helm releases in your cluster, enriches alerts with AI-generated upgrade risk assessments via Claude, and notifies your team through Microsoft Teams and PagerDuty.

## Description

The eol-operator watches every Helm release in the cluster by reading Helm's internal Secrets. When a release falls behind the latest version published on ArtifactHub, the operator creates a `HelmEOLAlert` custom resource and:

1. Calls the Claude API to generate a structured risk report: upgrade path, breaking changes, CVEs fixed, and a 1-10 risk score.
2. Sends the enriched alert to configured notification channels (Teams and/or PagerDuty).
3. Polls every 6 hours; when the release is finally upgraded, the alert is automatically deleted.

### Severity thresholds

| Severity | Condition | Example |
|----------|-----------|---------|
| `minor`  | Same major version, patch or minor versions available | 1.4.0 installed, 1.7.2 latest |
| `major`  | One full major version behind | 13.x installed, 14.x latest |
| `eol`    | Two or more major versions behind (consider unsupported) | 13.x installed, 15.x latest |

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `ANTHROPIC_API_KEY` | No | Anthropic API key for AI enrichment. When absent, the operator sends notifications without the risk report. |
| `TEAMS_WEBHOOK_URL` | No | Power Automate HTTP-trigger webhook URL. Set to enable Microsoft Teams notifications. |
| `PD_ROUTING_KEY` | No | PagerDuty Events API v2 integration key (32 chars). Set to enable PagerDuty incidents. |

At least one of `TEAMS_WEBHOOK_URL` or `PD_ROUTING_KEY` should be set, otherwise alerts are created in the cluster but no external notifications are sent.

Store these values in a Kubernetes Secret and expose them as env vars on the operator Deployment — never commit them to git.

## Getting Started

### Prerequisites

- go version v1.24.0+
- docker version 17.03+
- kubectl version v1.11.3+
- Access to a Kubernetes v1.11.3+ cluster

### Sample HelmEOLAlert CR

The operator creates `HelmEOLAlert` objects automatically. You can also create them manually to test notifications or backfill alerts for releases the operator has not seen yet:

```yaml
apiVersion: helm.earnix.com/v1alpha1
kind: HelmEOLAlert
metadata:
  name: cert-manager
  namespace: cert-manager
spec:
  releaseName: cert-manager
  namespace: cert-manager
  chartName: cert-manager
  installedVersion: "1.11.0"
  latestVersion: "1.16.3"
  versionsBehind: 5
  severity: minor
```

After creation the operator reconciles the alert through the following phases:

```
Pending → Enriching → Notified → (deleted when release is upgraded)
                               → Acknowledged (manual, suppresses re-notification)
```

### Deploy on the cluster

**Build and push your image:**

```sh
make docker-build docker-push IMG=<some-registry>/eol-operator:tag
```

**Install the CRDs:**

```sh
make install
```

**Deploy the operator with your notification credentials:**

```sh
kubectl create secret generic eol-operator-secrets \
  --from-literal=ANTHROPIC_API_KEY=sk-ant-... \
  --from-literal=TEAMS_WEBHOOK_URL=https://... \
  --from-literal=PD_ROUTING_KEY=...

make deploy IMG=<some-registry>/eol-operator:tag
```

**Apply sample alerts:**

```sh
kubectl apply -k config/samples/
```

### Uninstall

```sh
kubectl delete -k config/samples/
make uninstall
make undeploy
```

## Project Distribution

### Bundle (single YAML)

```sh
make build-installer IMG=<some-registry>/eol-operator:tag
kubectl apply -f dist/install.yaml
```

### Helm Chart

```sh
kubebuilder edit --plugins=helm/v1-alpha
# Chart generated under dist/chart/
```

## Contributing

1. Fork the repo and create a feature branch.
2. Run `make test` (unit tests with envtest) and `make lint` before opening a PR.
3. E2E tests require a running cluster: `make test-e2e`.

**NOTE:** Run `make help` for all available targets.

More information: [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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
