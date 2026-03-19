# Trivy Scanner API

> Self-hosted CVE scanning as a service — one HTTP endpoint for every CI pipeline in your organization.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-green.svg)](https://fastapi.tiangolo.com/)

Most teams install Trivy directly in each CI job, scatter results across pipeline logs, and never build a consistent audit trail. As the number of pipelines grows, keeping Trivy versions in sync, enforcing uniform severity thresholds, and routing alerts to the right channel becomes a maintenance burden spread across every repository.

This project packages Trivy into a hardened FastAPI service that any pipeline can reach over HTTP. Upload an archive, get back a structured JSON report, and let the service handle persistence, alerting, and optional AI-assisted remediation — all from one place you control.

## Architecture

```
  CI Pipeline (GitHub / Bitbucket / GitLab / Jenkins)
       │
       │  POST /scan-and-store  (multipart archive + optional overrides)
       │  X-API-Key  or  OIDC Bearer Token
       ▼
 ┌─────────────────────────────────────────────────────┐
 │                  FastAPI Service                     │
 │                                                     │
 │  1. Authenticate request (API key / OIDC / open)    │
 │  2. Validate archive (size, extension, zip-slip)    │
 │  3. Extract to isolated temporary directory         │
 │  4. Run Trivy (fs / config / image mode)            │
 │  5. Evaluate severity thresholds → failed flag      │
 │  6. Persist enriched report                         │
 │  7. Fire webhook  (Slack / Teams / custom)          │
 │  8. Generate AI remediation  (optional)             │
 └──────────────────┬──────────────────────────────────┘
                    │
         ┌──────────┴──────────┐
         │                     │
         ▼                     ▼
      AWS S3               Local FS
   (production)          (development)
```

## Why a Service Instead of Bare Trivy?

| Concern | Direct Trivy per pipeline | This service |
|---------|--------------------------|--------------|
| Trivy version drift | Each repo pins its own | One container, one version |
| Severity enforcement | Per-repo copy-paste | Centrally configured, per-request overrides allowed |
| Audit trail | Scattered pipeline logs | Every report persisted to S3 or local disk |
| Alerting | Custom script per repo | Single webhook config covers all pipelines |
| AI remediation | Not feasible | Local LLM runs in the same process, no data leaves |
| Cloud credentials | Needed in every runner | Only the scanner service holds them |

## Quick Start

```bash
# 1. Build the image
docker build -t trivy-scanner .

# 2. Run with local storage (no AWS needed)
docker run -d --rm -p 8000:8000 \
  -e AUTH_MODE=api_key \
  -e SCANNER_API_KEY=dev-secret \
  -e STORAGE_BACKEND=local \
  -e LOCAL_STORAGE_PATH=/reports \
  -v "$(pwd)/reports:/reports" \
  trivy-scanner

# 3. Scan the current directory
python tools/trivy_scan_client.py . \
  --api-url http://localhost:8000/scan-and-store \
  --api-key dev-secret \
  --fail-on CRITICAL,HIGH
```

A JSON report lands in `./reports/` and the terminal prints severity counts alongside the report path. Exit code `2` means blocking vulnerabilities were found.

## How It Works

### 1. Upload & Validate

`POST /scan-and-store` accepts a `.tar.gz` or `.tgz` archive. Before any bytes are extracted the service:

- Rejects files larger than `MAX_ARCHIVE_SIZE_MB` (default 200 MB).
- Refuses extensions not in `ALLOWED_ARCHIVES`.
- Counts members before extraction; archives with more than 10,000 entries are rejected (DoS mitigation).
- Resolves every member path against the destination directory and aborts if any entry would escape it (zip-slip protection).
- Rejects symbolic and hard links outright.

Extraction happens inside a `tempfile.TemporaryDirectory` that is deleted when the request finishes, regardless of success or failure.

### 2. Trivy Invocation

`ScanOptions.as_command()` builds the Trivy argument list, respects `TRIVY_CACHE_DIR` so the vulnerability database is shared across scans, and applies a configurable `TRIVY_TIMEOUT_SECONDS`. The subprocess inherits only a sanitized copy of the environment. Trivy outputs JSON, which is parsed directly — a non-zero exit code surfaces as an HTTP 500 with the stderr text included for debuggability.

### 3. Severity Thresholds and the `failed` Flag

Two severity concepts are kept separate on purpose:

- `TRIVY_SEVERITY` — which severities Trivy should *report*.
- `TRIVY_FAIL_ON_SEVERITY` — which severities set `failed: true` in the response (and exit code `2` from the CLI client).

This lets you scan for all severities while only blocking the pipeline on CRITICAL findings. Per-request overrides (controlled by `ALLOW_REQUEST_OVERRIDES`) let individual pipelines tighten thresholds without changing the server configuration.

### 4. Report Persistence

Every report is decorated with `scanner_metadata` (scan mode, severity filter, requesting identity, `failed` flag) before storage. The `StorageProvider` abstract base class makes it straightforward to add Google Cloud Storage or Azure Blob Storage without touching the rest of the application — subclass it and update `get_storage_provider`.

### 5. Webhooks

After every scan the service POSTs to `WEBHOOK_URL` (if configured) with overall status, severity counts, report URI, and any AI recommendation. Slack incoming webhooks, Microsoft Teams connectors, and generic HTTP endpoints all accept this payload. Custom auth headers (e.g., `Authorization: Bearer <token>`) are supported via `WEBHOOK_HEADERS`.

### 6. AI Remediation

When `AI_REMEDIATION_ENABLED=true` and `AI_MODEL_PATH` points to a `.gguf` model file, the service loads it once at startup via `llama-cpp-python`. For each scan it builds a structured prompt from the top findings (capped at 10 to keep inference fast) and returns bullet-point remediation advice alongside the report. A 4-bit quantized 7B instruction model fits in roughly 5 GB of RAM and produces useful output in 5–15 seconds on CPU.

No vulnerability data ever leaves your infrastructure.

## Authentication

| Mode | How to Enable | Best For |
|------|--------------|---------|
| `api_key` | Set `SCANNER_API_KEY`; send `X-API-Key` header | Simple shared secret for internal pipelines |
| `oidc` | Set `OIDC_ISSUER` and `OIDC_AUDIENCE` | GitHub Actions OIDC — no long-lived secrets |
| `none` | `AUTH_MODE=none` | Air-gapped or private networks |

The OIDC implementation fetches JWKS from `{issuer}/.well-known/jwks.json`, caches keys for one hour, and refreshes on unknown `kid` to handle key rotation gracefully.

## Configuration Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_MODE` | `api_key` | `api_key`, `oidc`, or `none` |
| `SCANNER_API_KEY` | — | Required when `AUTH_MODE=api_key` |
| `OIDC_ISSUER` | — | e.g. `https://token.actions.githubusercontent.com` |
| `OIDC_AUDIENCE` | — | Expected audience claim |
| `OIDC_ALGORITHMS` | `RS256` | Comma-separated signing algorithms |
| `STORAGE_BACKEND` | `s3` | `s3` or `local` |
| `S3_BUCKET_NAME` | — | Required when using S3 |
| `S3_REPORT_PREFIX` | `reports/` | Folder prefix inside the bucket |
| `LOCAL_STORAGE_PATH` | `./reports` | Directory for JSON reports |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | — | Standard AWS credentials (IAM role also accepted) |
| `TRIVY_BINARY` | `trivy` | Path to the Trivy executable |
| `TRIVY_DEFAULT_MODE` | `fs` | Scan mode: `fs`, `config`, or `image` |
| `TRIVY_SEVERITY` | `CRITICAL,HIGH` | Severities included in the report |
| `TRIVY_FAIL_ON_SEVERITY` | — | Severities that set `failed: true` |
| `TRIVY_IGNORE_UNFIXED` | `true` | Skip vulnerabilities with no fix available |
| `TRIVY_TIMEOUT_SECONDS` | `600` | Kill Trivy if it exceeds this threshold |
| `TRIVY_ADDITIONAL_ARGS` | — | Extra CLI flags appended to every invocation |
| `TRIVY_IGNORE_POLICY_PATH` | — | Path to a mounted Rego ignore policy |
| `TRIVY_CACHE_DIR` | — | Shared DB cache path (speeds up repeated scans) |
| `MAX_ARCHIVE_SIZE_MB` | `200` | Hard cap on uploaded archive size |
| `ALLOWED_ARCHIVES` | `.tar.gz,.tgz` | Accepted archive extensions |
| `ALLOW_REQUEST_OVERRIDES` | `true` | Let pipelines override scan options per request |
| `WEBHOOK_URL` | — | Endpoint to notify after each scan |
| `WEBHOOK_HEADERS` | — | `Header:Value` pairs, comma-separated |
| `AI_REMEDIATION_ENABLED` | `false` | Enable AI summaries |
| `AI_MODEL_PATH` | — | Path to a `.gguf` model file |
| `AI_CONTEXT_TOKENS` | `2048` | Model context window size |
| `AI_MAX_OUTPUT_TOKENS` | `512` | Maximum tokens generated |

## API Reference

### `POST /scan-and-store`

**Request** — `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `file` | file | Yes | `.tar.gz` or `.tgz` archive |
| `scan_mode` | string | No | Override default Trivy mode |
| `severity` | string | No | Comma-separated severity override |
| `ignore_unfixed` | string | No | `true` or `false` |
| `fail_on_severity` | string | No | Comma-separated severities that trigger `failed: true` |
| `trivy_ignore_policy` | string | No | Inline Rego ignore policy |

**Response**

```json
{
  "status": "completed",
  "failed": false,
  "report_uri": "s3://my-bucket/reports/2024-11-01T120000Z-project.json",
  "severity_counts": {
    "CRITICAL": 0,
    "HIGH": 2,
    "MEDIUM": 7,
    "LOW": 12,
    "UNKNOWN": 0
  },
  "ai_recommendation": "- Upgrade requests to >=2.32.0 to fix CVE-2024-35195\n- Pin cryptography to >=42.0.4"
}
```

When `failed` is `true` the response also includes `"message": "Failing due to configured severity threshold"`. The AI recommendation field is only present when the AI feature is enabled and the model loaded successfully.

### `GET /healthz`

Returns `{"status": "ok"}`. Consumed by the Docker `HEALTHCHECK` directive and load-balancer health probes.

## Pipeline Integration

### CLI Helper

`tools/trivy_scan_client.py` creates a tar archive from a local directory, uploads it, prints the full JSON result, and exits with code `2` when the scan reports blocking vulnerabilities so your pipeline can fail fast. It requires only `httpx` — no extra dependencies.

```bash
python tools/trivy_scan_client.py /path/to/project \
  --api-url "https://scanner.example.com/scan-and-store" \
  --api-key "$SCANNER_API_KEY" \
  --severity "CRITICAL,HIGH,MEDIUM" \
  --fail-on "CRITICAL" \
  --exclude ".git,node_modules,dist" \
  --output scan-report.json
```

Exit codes: `0` = passed, `1` = request error, `2` = blocking vulnerabilities found.

### GitHub Actions

`.github/workflows/trivy-scan.yml` is a ready-to-use workflow that runs on every push and pull request. Configure `SCANNER_API_URL` and `SCANNER_API_KEY` as repository secrets and the JSON report is uploaded as a workflow artifact.

For keyless authentication, switch to `AUTH_MODE=oidc` on the server with `OIDC_ISSUER=https://token.actions.githubusercontent.com`. Drop the `SCANNER_API_KEY` secret entirely — the Actions OIDC token is validated automatically.

### Bitbucket Pipelines

`examples/bitbucket-pipelines.yml` mirrors the GitHub Actions setup. Add `SCANNER_API_URL` and `SCANNER_API_KEY` as secured repository variables; the `scan-report.json` is captured as a pipeline artifact.

### GitLab / Jenkins / Others

Any runner that can execute `pip install httpx && python tools/trivy_scan_client.py ...` works out of the box. Jenkins users can publish the output JSON via the `archiveArtifacts` step.

For co-located deployments (runner and scanner on the same host or in the same Kubernetes pod), point `--api-url` at `http://localhost:8000/scan-and-store` to eliminate egress entirely.

## Webhook Payload

```json
{
  "status": "failed",
  "severity_counts": {
    "CRITICAL": 1,
    "HIGH": 3,
    "MEDIUM": 5,
    "LOW": 0,
    "UNKNOWN": 0
  },
  "report_uri": "s3://my-bucket/reports/2024-11-01T120000Z-project.json",
  "ai_recommendation": "- Upgrade openssl to >=3.3.1 to address CVE-2024-4603"
}
```

Slack incoming webhooks, Microsoft Teams connectors, and PagerDuty event APIs all accept this shape directly. For services that require a specific auth header, set `WEBHOOK_HEADERS=Authorization:Bearer <token>`.

## AI Remediation (Optional)

1. Install the optional dependency: `pip install -r requirements-ai.txt`
2. Download a GGUF model — `TheBloke/CodeLlama-7B-Instruct-GGUF` (Q4_K_M quantization) is a good starting point and fits comfortably on a 2-vCPU, 8 GB RAM instance.
3. Set `AI_REMEDIATION_ENABLED=true` and `AI_MODEL_PATH=/models/codellama-7b-instruct.Q4_K_M.gguf`.

The model loads once at startup and is reused for every scan. The prompt is built from the top 10 findings (title, severity, CVE ID, truncated description) and asks for bullet-point remediation steps. Treat the output as advisory — it reliably surfaces useful version pins and configuration suggestions, but always review before merging to production.

## Extending

### Adding a Storage Backend

Subclass `StorageProvider` in `app/storage.py` and register it in `get_storage_provider`:

```python
class GCSStorageProvider(StorageProvider):
    def store_report(self, key: str, content: Dict) -> str:
        blob = self.bucket.blob(key)
        blob.upload_from_string(json.dumps(content), content_type="application/json")
        return f"gs://{self.bucket.name}/{key}"
```

### Adding an Auth Strategy

Add a new async callable to `app/auth.py` and expose it via the `AUTH_MODE` switch in `get_auth_dependency`. The callable must be compatible with FastAPI's dependency injection and return a dict containing at least a `sub` key (used as the requesting identity in stored reports).

## Local Development

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt

export AUTH_MODE=api_key
export SCANNER_API_KEY=dev-secret
export STORAGE_BACKEND=local
export LOCAL_STORAGE_PATH=./.local-reports

uvicorn main:app --reload
```

## Testing

```bash
pytest
```

The test suite uses `fastapi.TestClient`, monkeypatches `run_trivy_scan` with a fixture that returns a controlled report dict, and covers both the clean-scan and blocking-severity paths. No live Trivy binary or cloud credentials are required.

## Observability

The service logs all scan requests at INFO level including filename, requesting identity, and the full Trivy command. To go further:

- **Prometheus metrics** — wrap `run_trivy_scan` to emit `scan_duration_seconds` (histogram) and `vulnerability_total` (counter labelled by severity).
- **Structured logging** — swap `basicConfig` for `python-json-logger` and ship to Loki, CloudWatch Logs, or Datadog.
- **Distributed tracing** — add `opentelemetry-instrumentation-fastapi` to correlate scanner spans with upstream pipeline traces.
- **Alerting** — the webhook payload maps cleanly to PagerDuty events or Opsgenie alerts when `failed` is `true`.
