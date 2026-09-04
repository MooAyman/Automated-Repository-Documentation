# Repository Documentation

An ARK (Agentic Runtime for Kubernetes) application that turns a GitHub or GitLab repository into grounded developer documentation and a standalone HTML file.

Most repositories still depend on a README that drifts from the code. This project collects the current source, asks a model to fill a strict JSON schema from that dump only, and renders the result to HTML. You give it a URL; you do not copy intermediate JSON.

## Architecture

```text
User
  ↓  one ARK Query
Agent/repository-pipeline          orchestrator (no analysis, no HTML)
  ↓  Agent-as-Tool
Agent/repository-documentation     analysis + spec.outputSchema JSON
  ↓  HTTP Tool
Tool/repository-collector          clone, filter, deterministic text dump
  ↓
Structured JSON
  ↓  HTTP Tool
Tool/documentation-renderer        deterministic HTML (no LLM)
  ↓  /mnt/output/<repo>.html
Windows host
  C:\Users\moham\source\repos\repository-documentation\out\<repo>.html
```


| Resource                   | Kind          | Responsibility                                                                                                                            |
| -------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `repository-pipeline`      | Agent         | Extract URL and optional `ref`, call the documentation Agent once, pass the JSON unchanged to the renderer, return the artifact filename. |
| `repository-documentation` | Agent         | Call the collector once, analyse the dump, fill `spec.outputSchema`.                                                                      |
| `repository-collector`     | Tool (`http`) | Clone a Git URL, filter secrets/binaries/caches, emit a deterministic text dump.                                                          |
| `documentation-renderer`   | Tool (`http`) | Validate the JSON and render standalone HTML.                                                                                             |
| ARK / Kubernetes           | runtime       | Agents, Tools, `Model/default`, the collector Deployment/Service, and the renderer Service (host-backed when `hostDocker` is true).       |


Collector and renderer are Tools, not Agents: they are deterministic HTTP services. They must not invent files, rewrite documentation, or call a model. The documentation Agent owns analysis; the pipeline Agent only sequences the two stages. ARK 0.1.68 treats an Agent's `outputSchema` as that Agent's final response, so the documentation Agent cannot call the renderer in the same turn. The pipeline Agent calls the documentation Agent as an Agent Tool, then calls the renderer.

## Features

- One-command ARK pipeline (`ark query agent/repository-pipeline …`)
- Public GitHub repositories
- Public GitLab (`gitlab.com` and self-hosted) repositories
- Private / self-hosted GitLab via a cluster Secret (`GITLAB_TOKEN`); the token is not sent with each query
- Optional `ref` (branch, tag, or commit); omitted `ref` uses the default branch
- Missing `ref` fails; the collector does not fall back
- Strict structured JSON (`Agent.spec.outputSchema`)
- Deterministic HTML rendering (no LLM)
- HTML written to the Windows host `out/` directory
- Query and tool-call visibility in the ARK Dashboard



## Prerequisites

Verified on this machine:

- Docker Desktop Kubernetes
- ARK **0.1.68** (`ark --version`), with `Model/default` Available
- `kubectl`, `helm`, `ark`, Docker, Python 3
- Namespace `default` (Tool URLs are hardcoded to `*.default.svc.cluster.local`)

This chart does not ship a Model or API keys. It reuses the Model installed with ARK.

## Installation

```powershell
git clone https://github.com/MooAyman/Automated-Repository-Documentation.git
cd Automated-Repository-Documentation

kubectl cluster-info
ark --version
kubectl get model default
```

Build images (Docker Desktop uses the local image store; no `docker push` is required). Tags match `values.yaml`:

```powershell
docker build -t localhost:5000/repository-documentation-repository-collector:m4 tools/repository-collector
docker build -t localhost:5000/repository-documentation-documentation-renderer:m5 tools/documentation-renderer
```

Publish the renderer on the Windows host so `/mnt/output` is the repo `out/` directory (Docker Desktop Kubernetes cannot `hostPath` a Windows folder):

```powershell
New-Item -ItemType Directory -Force -Path .\out | Out-Null

docker run -d --name documentation-renderer-host --restart=unless-stopped `
  -p 18080:8080 -e OUTPUT_DIR=/mnt/output `
  -v C:\Users\moham\source\repos\repository-documentation\out:/mnt/output `
  localhost:5000/repository-documentation-documentation-renderer:m5
```

The bind mount must be this checkout's `out/` directory and must match `values.yaml` `renderer.output.windowsPath`.

Install the chart:

```powershell
helm upgrade --install repository-documentation . --namespace default --wait --timeout 6m
```

Verify:

```powershell
kubectl get agent repository-pipeline repository-documentation
kubectl get tool repository-documentation repository-collector documentation-renderer
```

Expected: both Agents `Available`; Tools `repository-collector` (http), `repository-documentation` (agent), and `documentation-renderer` (http) Ready.

With `renderer.output.hostDocker: true` (this chart's default), there is no in-cluster renderer Deployment. Confirm the host container instead:

```powershell
docker ps --filter name=documentation-renderer-host
kubectl get svc,endpoints documentation-renderer
```



## GitLab private repositories

Public GitHub and public GitLab URLs work with no extra configuration.

Private GitLab (including self-hosted) uses a Kubernetes Secret. Create it once; do not put the token in queries, Tool input, `values.yaml`, or Git.

```powershell
kubectl create secret generic gitlab-token `
  --from-literal=token=<YOUR_GITLAB_PAT> `
  --namespace default

helm upgrade --install repository-documentation . --namespace default `
  --set gitlab.tokenSecret.name=gitlab-token `
  --wait --timeout 6m
```

`values.yaml` keys:

```yaml
gitlab:
  tokenSecret:
    name: ""      # set to gitlab-token (or pass --set above)
    key: token
```

The collector injects `GITLAB_TOKEN` from that Secret and authenticates with a host-scoped HTTP `Authorization` header. The token is never placed in the clone URL, git argv, logs, or the Agent prompt.

`ref` is a branch, tag, or commit. If omitted, the default branch is used. If the ref does not exist, collection fails.

## Usage

```powershell
ark query agent/repository-pipeline "Document this repository: https://github.com/MooAyman/github-mcp-chatbot"
```

That single Query runs `repository-pipeline` → `repository-documentation` → `repository-collector` → `documentation-renderer` → HTML. You do not retrieve or paste the JSON. There is no standalone documentation Query.

Optional ref (also accepted as `branch: …`):

```powershell
ark query agent/repository-pipeline "Document this repository: https://gitlab.example.com/group/project ref: develop"
```



## Output

Pipeline success looks like:

```text
✓ Repository collected
✓ Documentation generated
✓ HTML rendered

Output:
github-mcp-chatbot.html
```

The file is:

```text
C:\Users\moham\source\repos\repository-documentation\out\github-mcp-chatbot.html
```

Mechanism (not a Windows Kubernetes `hostPath`):

```text
Windows host:
C:\Users\moham\source\repos\repository-documentation\out
        ↓  docker bind mount
container documentation-renderer-host:
/mnt/output
        ↑
in-cluster Service documentation-renderer:8080
        → Endpoints 192.168.65.254:18080  (documentation-renderer-host)
```

`values.yaml` `renderer.output.hostDocker`, `hostIP` (`192.168.65.254`), and `hostPort` (`18080`) wire that Service. Filenames are derived from the repository name and sanitized (no path traversal).

## Generated documentation

The documentation Agent fills `spec.outputSchema`. The renderer turns that JSON into HTML with these sections:

1. Repository Overview
  - Quick Start
2. Repository Structure
3. Tools & Technologies Used
4. Core Concepts & Architecture
  - Request Flow
  - Build & Packaging Flow
5. Categorized Technical Information
  - Main APIs / Endpoints
  - Main Services / Mediators
  - DTOs / Schemas / Metadata
  - Security Components
  - Configurations
  - Entry Points
  - Tests
  - Risks / Technical Debt
6. Developer Onboarding Guide
  - First 30 Minutes
  - Production Bug Investigation
  - Critical Files
  - Common Mistakes

Grounding rules (documentation Agent prompt):

- The collector dump is the only source of truth.
- Do not invent files, functions, endpoints, env vars, commands, or behaviour.
- Cite relative paths for concrete claims.
- Mark inferences (`Inferred: …`).
- If something cannot be determined, say so.
- Treat excluded files as unseen.



## Observability

ARK Dashboard (installed with ARK 0.1.68):

```powershell
kubectl port-forward svc/ark-dashboard 3000:3000
```

Open [http://localhost:3000](http://localhost:3000) to inspect Agents, Tools, and Queries.

Live tool-call events for a Query:

```powershell
ark query agent/repository-pipeline "Document this repository: https://github.com/MooAyman/github-mcp-chatbot" -o events-pretty
```

The normal Query response stays short; it does not embed the HTML.

## Error handling

Collector HTTP statuses:


| Status | Meaning                                                                 |
| ------ | ----------------------------------------------------------------------- |
| 400    | Invalid URL, empty input, or unclassified git failure                   |
| 401    | Git authentication failed (git 401/403 and similar access-denied cases) |
| 404    | Repository not found, or requested `ref` does not exist                 |
| 413    | Request body too large                                                  |
| 504    | Clone timed out                                                         |


The pipeline Agent stops after a failed stage and does not call the renderer or invent HTML. A missing `ref` does not fall back to another branch.

## Testing

```powershell
python tests/test_collector.py            # collector, renderer unit tests, pipeline config
python tests/test_collector.py --network  # live clone of the GitHub test repo
python tests/test_collector.py --e2e      # deployed repository-pipeline Query and HTML artifact
```

Optional private GitLab collector test (local process; token stays in the environment, not in Git). This is separate from the cluster Secret used by the deployed collector:

```powershell
$env:GITLAB_TOKEN="<YOUR_GITLAB_PAT>"
$env:GITLAB_E2E_REPOSITORY="https://gitlab.example.com/group/project"
$env:GITLAB_E2E_REF="main"
python tests/test_collector.py
```



## Security

- GitLab PAT: Kubernetes Secret only; host-scoped git `extraHeader`; redacted from URLs, argv, child env, and logs.
- Collector drops `.env`, private keys, binaries, lockfiles, and dependency/cache/`.git` directories; `.env.example` is kept.
- Renderer HTML-escapes repository content (no raw script injection).
- Collector Deployment: non-root, read-only root filesystem, dropped capabilities. The renderer image also runs as uid 1001; with `hostDocker` it is the host container `documentation-renderer-host`, not an in-cluster pod.
- No API keys or tokens in this repository. `.env` is gitignored.



## Limitations

- The full dump is one model request. Repositories larger than the context window are capped at `max_total_bytes` (250000) / `max_file_bytes` (80000) in `tools/repository-collector.yaml`.
- Tool HTTP URLs are hardcoded to the `default` namespace.
- Docker Desktop Kubernetes cannot mount a Windows directory as a pod `hostPath`; HTML reaches the host through the Docker bind above.
- Local filesystem collection exists inside the collector container only. It is not a supported user-facing pipeline input.



## Future work

Not implemented as user-facing features:

- Local repository support (host-path / workstation repos as pipeline input)
- Incremental documentation for repositories larger than the collector byte budget
- LangFuse for observability.
- Files Prioritization
- UI
- Private GitHub
- LLM Analyzer

