# Langfuse Cloud Observability

This project uses ARK's built-in OpenTelemetry support to export LLM observability data to Langfuse Cloud.

No Langfuse SDK is required in the application code.

## Architecture

```text
ARK
 ├── repository-pipeline
 │     └── repository-documentation
 │
 └── OpenTelemetry
          ↓
    Langfuse Cloud
```

## Langfuse Cloud Setup

Create a Langfuse Cloud project and obtain:

* Public Key
* Secret Key

## Kubernetes Configuration

Create the OpenTelemetry Secret in the `ark-system` namespace:

```powershell
$auth = "PUBLIC_KEY:SECRET_KEY"
$base64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($auth))

kubectl create secret generic otel-environment-variables `
  -n ark-system `
  --from-literal=OTEL_EXPORTER_OTLP_ENDPOINT="https://cloud.langfuse.com/api/public/otel" `
  --from-literal=OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic $base64"
```

Create the same Secret in the `default` namespace:

```powershell
kubectl create secret generic otel-environment-variables `
  -n default `
  --from-literal=OTEL_EXPORTER_OTLP_ENDPOINT="https://cloud.langfuse.com/api/public/otel" `
  --from-literal=OTEL_EXPORTER_OTLP_HEADERS="Authorization=Basic $base64"
```

The actual credentials must never be stored in Git.

## Restart ARK Components

Restart the ARK components so they load the OpenTelemetry configuration:

```powershell
kubectl rollout restart deployment/ark-controller -n ark-system
kubectl rollout restart deployment/ark-completions -n ark-system
```

Wait until both deployments are ready:

```powershell
kubectl get pods -n ark-system | findstr "ark-controller ark-completions"
```

## Verification

Run the repository documentation pipeline:

```powershell
ark query agent/repository-pipeline "Document this repository: <REPOSITORY_URL>"
```

A successful run should complete the normal pipeline:

```text
✓ Repository collected
✓ Documentation generated
✓ HTML rendered
```

Then open the Langfuse Cloud project and verify that a new trace appears.

The trace should provide visibility into the ARK workflow and LLM activity, including token usage and cost when available from the model/provider telemetry.

## Security

Never commit:

* Langfuse Public/Secret keys
* Base64-encoded credentials
* Kubernetes Secrets containing credentials

Only the setup instructions and non-sensitive configuration belong in this repository.
