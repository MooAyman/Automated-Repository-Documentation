# Repository Documentation

An ARK application that turns a Git repository into developer documentation.

```
repository URL
      │
      ▼
Agent  repository-documentation          (ark.mckinsey.com/v1alpha1, kind: Agent)
      │  calls
      ▼
Tool   repository-collector              (kind: Tool, type: http)
      │  POST /collect
      ▼
Service repository-collector             (Deployment + Service, in cluster)
      │  clones, filters, serialises
      ▼
repository content (plain text)
      │
      ▼
LLM  (modelRef: default)
      │
      ▼
developer documentation (Markdown, six sections)
```

Everything is a Kubernetes resource. The only application code is the collector
service, which exists solely because an ARK `Tool` of `type: http` needs an
endpoint to call.

## Layout

```
repository-documentation/
├── agents/repository-documentation.yaml     # ARK Agent + documentation prompt
├── tools/
│   ├── repository-collector.yaml            # ARK Tool (type: http)
│   └── repository-collector/                # the service the Tool calls
│       ├── collector.py                     #   repository acquisition + filtering
│       ├── server.py                        #   two-endpoint HTTP wrapper
│       └── Dockerfile
├── queries/document-github-mcp-chatbot.yaml # ARK Query (end-to-end test)
├── templates/repository-collector.yaml      # Deployment + Service for the collector
├── templates/00-rbac.yaml … 06-queries.yaml # generated: publish agents/tools/queries
├── tests/test_collector.py                  # collector unit tests + deployed e2e check
├── values.yaml
└── Chart.yaml
```

`templates/0*.yaml` come from `ark generate project` and publish every YAML file
in `agents/`, `tools/` and `queries/` as Helm hooks in dependency order.

## Prerequisites

- A cluster with ARK installed and a `Model` named `default` in the target
  namespace. `ark status` should report the controller ready and a default model.
- Docker, `kubectl` and `helm`.

This chart deliberately ships no `Model`; it reuses the one the ARK install
already provides, so no API keys live in this repository.

## Deploy

```bash
# 1. Build the collector image into the cluster's image store
cd tools/repository-collector
docker build -t localhost:5000/repository-documentation-repository-collector:latest .

# 2. Install the chart
cd ../..
helm upgrade --install repository-documentation . --namespace default --wait --timeout 6m
```

On Docker Desktop the locally built image is visible to the kubelet, so
`imagePullPolicy: IfNotPresent` resolves it without a registry. On kind or
minikube, load the image first (`kind load docker-image …` / `minikube image
load …`).

Verify:

```bash
kubectl get agents
kubectl get tools
kubectl get pods -l component=collector
```

## Run

The chart installs an ARK `Query` that runs the flow once on install. To run it
again:

```bash
kubectl delete query document-github-mcp-chatbot
kubectl apply -f queries/document-github-mcp-chatbot.yaml
kubectl get query document-github-mcp-chatbot -o jsonpath='{.status.response.content}'
```

Or ad hoc, against any repository:

```bash
ark query agent/repository-documentation \
  "Generate developer documentation for https://github.com/MooAyman/github-mcp-chatbot"
```

## Test

```bash
python tests/test_collector.py            # collector filtering, determinism, errors
python tests/test_collector.py --network  # also clones the target repository
python tests/test_collector.py --e2e      # also checks the deployed query's output
```

## How the pieces connect

**The Agent reaches the collector through the ARK Tool**, declared as an explicit
tool type on the agent:

```yaml
tools:
  - type: http
    name: repository-collector
```

**The Tool reaches the service over HTTP.** The ARK controller performs the call
from the `ark-system` namespace, so `spec.http.url` must be a fully qualified
cluster DNS name:

```
http://repository-collector.default.svc.cluster.local:8080/collect
```

The LLM's arguments are interpolated into the request body with ARK's Go template
syntax (`{{.input.repository}}`); size limits come from `bodyParameters`. If you
deploy to a different namespace, update that URL — `tools/*.yaml` is copied
verbatim by the chart and cannot interpolate Helm values.

## The collector

`collector.py` is independent of ARK and of the LLM. Given a GitHub URL, a GitLab
URL or a local path it produces one deterministic text document containing the
repository name, its directory tree, the list of excluded files, and the contents
of every included file preceded by its relative path.

It excludes `.git`, dependency/build/cache directories, binaries (by extension and
by NUL-byte sniff), generated lock files, and credential files such as `.env` and
private keys — while allowing `.env.example`. Files above `max_file_bytes` are
skipped, output is capped at `max_total_bytes`, line endings are normalised to LF,
and paths are sorted lexicographically so the same repository state always yields
byte-identical output.

Every exclusion is reported in the output, so the agent can tell the reader what
it was not shown.

### Private GitLab repositories

Authentication is infrastructure configuration, not Tool input. Create a
Kubernetes Secret holding a GitLab personal access token, then point the chart
at it:

```bash
kubectl create secret generic gitlab-token \
  --from-literal=token=<GITLAB_PAT> \
  --namespace default

helm upgrade --install repository-documentation . --namespace default \
  --set gitlab.tokenSecret.name=gitlab-token
```

The collector reads `GITLAB_TOKEN` from that Secret and authenticates to GitLab
with a host-scoped HTTP `Authorization` header. The token is never placed in the
repository URL, git command-line arguments, logs, the ARK Tool schema, or the
Agent prompt. Leave `gitlab.tokenSecret.name` empty for public GitHub.

To exercise a real private GitLab repository from this machine:

```bash
set GITLAB_TOKEN=<GITLAB_PAT>
set GITLAB_E2E_REPOSITORY=https://gitlab.example.com/group/project
set GITLAB_E2E_REF=main
python tests/test_collector.py
```

`GITLAB_E2E_REF` may be a branch, a tag, or a commit SHA. The default suite
passes when those variables are unset.

## Configuration

| Value | Default | Purpose |
| --- | --- | --- |
| `collector.name` | `repository-collector` | Service name; must match the Tool URL |
| `collector.port` | `8080` | Service port; must match the Tool URL |
| `collector.image.repository` | `localhost:5000/repository-documentation-repository-collector` | Image to run |
| `collector.workspaceSizeLimit` | `2Gi` | Disk budget for clones |
| `collector.localRepoRoot` | `""` | Restrict local-path collection to this directory |
| `gitlab.tokenSecret.name` | `""` | Existing Secret that holds a GitLab PAT |
| `gitlab.tokenSecret.key` | `token` | Key inside that Secret |

Per-request limits (`max_file_bytes`, `max_total_bytes`) are set in
`tools/repository-collector.yaml` under `http.bodyParameters`.

## Known limitations

- The whole repository is sent to the model in one request, so repositories
  larger than the model's context window will be truncated by `max_total_bytes`.
  Chunked or hierarchical analysis is not implemented.
- The six-section structure is enforced by the prompt, not by
  `spec.outputSchema`. With `gpt-4o-mini` this required an explicit heading
  checklist; a stronger model or a structured output schema would be more robust.
- GitLab private repositories require a Kubernetes Secret and
  `gitlab.tokenSecret.name`. Public GitHub collection does not.
- The Tool URL hardcodes the `default` namespace.
