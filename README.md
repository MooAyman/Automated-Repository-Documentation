# Repository Documentation

An ARK (Agentic Runtime for Kubernetes) application that turns a GitHub or GitLab repository into grounded developer documentation and a standalone HTML file.

Most repositories still depend on a README that drifts from the code. This project collects the current source, asks a model to fill a strict JSON schema from that dump only, and renders the result to HTML. You give it a URL; you do not copy intermediate JSON.

You can run the same pipeline from the CLI or from the host Streamlit UI.

## Architecture

```text
User  (ark query  or  Streamlit UI)
  ↓  Streamlit: host-side URL/ref validation + last-documented SHA registry
  ↓  same SHA → already_documented (no Query); otherwise one ARK Query
Agent/repository-pipeline          orchestrator (no analysis, no HTML)
  ↓  Agent-as-Tool
Agent/repository-documentation     analysis + spec.outputSchema JSON
  ↓  HTTP Tool
Tool/repository-collector          clone, filter, deterministic text dump
  ↓  HTTP Tool
Tool/repository-analyzer           Python AST + unique cross-file references (sanitized input only)
  ↓  HTTP Tool
Tool/repository-map                deterministic modules/symbols/relationships (analyzer JSON only)
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
| `repository-documentation` | Agent         | Call collector, analyzer, then map; analyse the dump (source of truth) plus that deterministic evidence; fill `spec.outputSchema`.         |
| `repository-collector`     | Tool (`http`) | Clone a Git URL, filter secrets/binaries/caches, emit a deterministic text dump. Same-pipeline `/changes`+`/collect` reuse one workspace. |
| `repository-analyzer`      | Tool (`http`) | Conservative Python AST on already-sanitized files/dump. Resolves unique same-file and imported cross-file references. Does not clone.    |
| `repository-map`           | Tool (`http`) | Deterministic Repository Map from analyzer JSON: modules, symbols, relationships, tree. No clone, no AST, no LLM.                         |
| `repository-changes`       | Tool (`http`) | Deterministic file changes between two commit SHAs (same collector service and inclusion rules). Empty previous SHA is a first/full run. |
| `documentation-renderer`   | Tool (`http`) | Validate the JSON and render standalone HTML.                                                                                             |
| Streamlit UI (`app/`)      | host client   | Validates URL/ref, consults the last-documented SHA registry, applies one Query when needed, then opens or downloads `out/<repo>.html`. |
| ARK / Kubernetes           | runtime       | Agents, Tools, `Model/default`, collector/analyzer/map Deployments/Services, and the renderer Service (host-backed when `hostDocker` is true). |

Collector, analyzer, map, and renderer are Tools, not Agents: they are deterministic HTTP services. They must not invent files, rewrite documentation, or call a model. The analyzer accepts only already-sanitized content (never a clone). The map accepts only analyzer JSON. The documentation Agent owns analysis; the pipeline Agent only sequences documentation then render. ARK 0.1.68 treats an Agent's `outputSchema` as that Agent's final response, so the documentation Agent cannot call the renderer in the same turn. The pipeline Agent calls the documentation Agent as an Agent Tool, then calls the renderer.

The Streamlit app does not call the collector, analyzer, map, or renderer. It validates the URL and optional ref, then submits the same Query the CLI uses unless that repository is already documented at the current commit. The last documented SHA is stored in `state/documentation-registry.json` (not Streamlit memory and not the HTML file). A raw `ark query` CLI run does not consult this registry.

## Features

- One-command ARK pipeline (`ark query agent/repository-pipeline …`)
- Streamlit UI that validates the URL/ref, then submits that same Query and reads the HTML from `out/`
- Persistent last-documented commit SHA per repository (JSON registry; SHA is written only after a successful generation)
- Same repository + same SHA returns `already_documented` and skips regeneration
- Deterministic URL and ref validation before a Query starts (no LLM)
- Public GitHub repositories
- Public GitLab (`gitlab.com` and self-hosted) repositories
- Private / self-hosted GitLab via a cluster Secret (`GITLAB_TOKEN`); the token is not sent with each query
- Optional `ref` (branch, tag, or commit); omitted `ref` uses the default branch
- Missing `ref` fails; the collector does not fall back
- Deterministic Git change detection between two commit SHAs (added/modified/deleted/renamed), filtered by the same collector inclusion rules as `/collect`; no previous SHA means a first/full run
- Same-pipeline `/changes` and `/collect` reuse one clone; a missing previous SHA is fetched into the shallow checkout without a full clone
- Deterministic regex redaction of secrets and PII in the collector dump before it reaches the model
- Deterministic JSON/YAML field redaction by sensitive key names before the dump reaches the model
- Conservative Python AST analysis (classes, functions, imports, unique cross-file references) on already-sanitized source only
- Deterministic Repository Map (modules, symbols, relationships, file tree) built from analyzer JSON only
- Dump-grounded documentation prompt with three evidence levels: confirmed, `Inferred:`, and `Not determinable from the repository.` as a last resort
- Strict structured JSON (`Agent.spec.outputSchema`)
- Deterministic HTML rendering (no LLM)
- HTML written to the Windows host `out/` directory
- Query and tool-call visibility in the ARK Dashboard
- Optional Langfuse Cloud traces via ARK OpenTelemetry (no Langfuse SDK in this repo)

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
docker build -t localhost:5000/repository-documentation-repository-collector:m12 tools/repository-collector
docker build -t localhost:5000/repository-documentation-repository-analyzer:m2 tools/repository-analyzer
docker build -t localhost:5000/repository-documentation-repository-map:m2 tools/repository-map
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
kubectl get tool repository-documentation repository-collector repository-analyzer repository-map repository-changes documentation-renderer
```

Expected: both Agents `Available`; Tools `repository-collector` (http), `repository-analyzer` (http), `repository-map` (http), `repository-changes` (http), `repository-documentation` (agent), and `documentation-renderer` (http) Ready.

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

### CLI

```powershell
ark query agent/repository-pipeline "Document this repository: https://github.com/MooAyman/github-mcp-chatbot"
```

That single Query runs `repository-pipeline` → `repository-documentation` → `repository-collector` → `repository-analyzer` → `repository-map` → `documentation-renderer` → HTML. You do not retrieve or paste the JSON. There is no standalone documentation Query.

Optional ref (also accepted as `branch: …`):

```powershell
ark query agent/repository-pipeline "Document this repository: https://gitlab.example.com/group/project ref: develop"
```

### Streamlit UI

The UI is a host-side client. It needs `kubectl` access to the same cluster and namespace (`ARK_NAMESPACE`, default `default`).

```powershell
pip install -r app\requirements.txt
python -m streamlit run app\ui.py
```

Open [http://localhost:8501](http://localhost:8501). Enter a repository URL and an optional ref, then **Generate Documentation**. Invalid input is rejected before a Query is applied. The app applies one Query to `agent/repository-pipeline` (timeout 15m), waits for `done`, and reads the HTML from `out/`. **Open Preview** opens that file in a new browser tab. **Download HTML** saves it.

The UI does not change Agents, Tools, prompts, or schemas.

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

- The collector dump is the source of truth. Analyzer JSON and the Repository Map are extra deterministic evidence.
- Do not invent files, functions, endpoints, env vars, commands, or behaviour.
- Cite relative paths for concrete claims.
- Three evidence levels: confirmed (plain statement + path), `Inferred: …`, and `Not determinable from the repository.` only as a last resort.
- Document the interfaces that exist (HTTP, CLI, Agent/Tool, YAML/JSON/typed schemas). Do not require REST or a type named DTO.
- Treat excluded files as unseen.

## Observability

### ARK Dashboard

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

### Langfuse Cloud

ARK can export traces to Langfuse Cloud through its built-in OpenTelemetry support. This project does not include a Langfuse SDK. `ark-controller` and `ark-completions` already mount the optional Secret `otel-environment-variables`.

Create a Langfuse Cloud project, then create that Secret in `ark-system` and `default`. Do not commit keys. Full commands are in [`observability/langfuse-cloud.md`](observability/langfuse-cloud.md).

After creating or updating the Secret:

```powershell
kubectl rollout restart deployment/ark-controller -n ark-system
kubectl rollout restart deployment/ark-completions -n ark-system
```

Run a pipeline Query, then confirm a trace in the Langfuse Cloud project. Token usage and cost appear when the model/provider telemetry includes them.

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
python tests/test_collector.py            # collector, analyzer, map, renderer, validation, dump sanitization, pipeline config
python tests/test_collector.py --network  # live clone of the GitHub test repo
python tests/test_collector.py --e2e      # deployed repository-pipeline Query and HTML artifact
```

`--e2e` applies one Query to `repository-pipeline` and asserts exactly one successful `POST /collect` in collector logs since that Query started.

Optional private GitLab collector test (local process; token stays in the environment, not in Git). This is separate from the cluster Secret used by the deployed collector:

```powershell
$env:GITLAB_TOKEN="<YOUR_GITLAB_PAT>"
$env:GITLAB_E2E_REPOSITORY="https://gitlab.example.com/group/project"
$env:GITLAB_E2E_REF="main"
python tests/test_collector.py
```

## Project structure

```text
agents/                         ARK Agent CRs (pipeline + documentation)
app/                            Streamlit UI (host-side Query client)
  ui.py
  ark_client.py
  documentation_registry.py
  validation.py
  requirements.txt
  assets/aman-logo.png
state/                          Last-documented SHA registry (gitignored; not HTML)
observability/langfuse-cloud.md Langfuse Cloud OTEL setup
templates/                      Helm templates (RBAC, Tools, Agents, collector, analyzer, map, renderer Service)
tools/                          Tool CRs and HTTP service source
  repository-collector/
  repository-analyzer/
  repository-map/
  documentation-renderer/
tests/test_collector.py         Collector, analyzer, map, renderer, host validation, pipeline config, and --e2e
values.yaml
Chart.yaml
out/                            Generated HTML (host bind; not a pipeline input)
```

## Security

- GitLab PAT: Kubernetes Secret only; host-scoped git `extraHeader`; redacted from URLs, argv, child env, and logs.
- Streamlit UI rejects local paths and URLs with embedded credentials before a Query starts.
- Collector drops `.env`, private keys, binaries, lockfiles, and dependency/cache/`.git` directories; `.env.example` is kept.
- Collector dump: a deterministic regex sanitizer redacts API keys, tokens, JWTs, private keys, emails, phones, and card numbers before the dump is returned. JSON/YAML field names such as password, token, and api_key have their values redacted while keys are kept. Matched values are not logged. An optional Local LLM detector can add extra span findings after that pass; it is disabled by default (`LOCAL_LLM_ENABLED=false`) and is not required to run.
- Analyzer input is that sanitized dump or sanitized per-file content only. The analyzer does not clone, does not read raw collector entries, and does not emit source snippets, defaults, or call/decorator arguments.
- Repository Map input is analyzer JSON only. It does not clone, parse source, or emit snippets or secrets.
- Renderer HTML-escapes repository content (no raw script injection).
- Collector Deployment: non-root, read-only root filesystem, dropped capabilities. The renderer image also runs as uid 1001; with `hostDocker` it is the host container `documentation-renderer-host`, not an in-cluster pod.
- No API keys or tokens in this repository. `.env` is gitignored.
- Langfuse keys belong only in the cluster Secret `otel-environment-variables`, never in Git.

## Limitations

- The full dump is one model request. Collection uses a per-file cap (`max_file_bytes` 80000) and a 200 MiB total safety ceiling (`max_total_bytes` 209715200) in `tools/repository-collector.yaml`. The total ceiling omits remaining files; it does not truncate them. `/changes` does not apply the total ceiling.
- Tool HTTP URLs are hardcoded to the `default` namespace.
- Docker Desktop Kubernetes cannot mount a Windows directory as a pod `hostPath`; HTML reaches the host through the Docker bind above.
- Local filesystem collection exists inside the collector container only. It is not a supported user-facing pipeline input.
- The Streamlit UI requires a working `kubectl` context and a deployed chart; it is not an in-cluster service.
- The last-documented SHA registry is host-side (`state/documentation-registry.json`). `ark query` from the CLI still always runs the full pipeline.

## Future work

Not implemented as user-facing features:

### Documentation Quality

- Evidence / Source References

### Repository Coverage

- Intelligent File Selection & Prioritization
- Incremental documentation generation (change detection exists; affected-file analysis and doc merging do not)
- Local repository support (host-path / workstation repositories as pipeline input)
- Private GitHub repository support

### Architecture

- Additional programming-language analyzers (Python AST is implemented)
- JSON/YAML structural analyzers (not AST)
- Advanced semantic / data-flow / full call-graph resolution
- LLM-based architecture or business-component inference
- Multi-stage Repository Analysis
- LLM-based Repository Analyzer
- Multi-Agent Documentation Team

### Observability & Evaluation

- Automated Documentation Evals
