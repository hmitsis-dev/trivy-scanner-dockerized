# Trivy Docker API

A hardened, pluggable FastAPI service that scans uploaded archives with Trivy, persists the JSON report, triggers optional webhooks, and can generate first-pass remediation advice with a local open-source model. The service is CI-friendly and ships with helper scripts for GitHub Actions, Bitbucket Pipelines, or any generic runner.

## Features

- Multi-backend storage (AWS S3 or local filesystem) with a clean provider interface.
- Pluggable authentication (`API key`, `OIDC bearer`, or open access for internal networks).
- Secure archive handling (size limits, extension whitelisting, zip-slip and symlink protection).
- Configurable Trivy execution (mode, severities, ignore policy, cache path, per-request overrides).
- Optional webhook notifications and AI remediation summary using a free local model via `llama.cpp`.
- Shipping CLI (`tools/trivy_scan_client.py`) for pipelines and ready-to-copy GitHub/Bitbucket examples.

## Configuration

Set the following environment variables (only the ones relevant to your deployment are required):

| Variable | Required | Description |
| -------- | -------- | ----------- |
| `AUTH_MODE` | ✅ (default `api_key`) | `api_key`, `oidc`, or `none`. |
| `SCANNER_API_KEY` | ✅ when `AUTH_MODE=api_key` | Shared secret used in the `X-API-Key` header. |
| `OIDC_ISSUER` | ✅ when `AUTH_MODE=oidc` | Issuer URL (e.g. `https://token.actions.githubusercontent.com`). |
| `OIDC_AUDIENCE` | ✅ when `AUTH_MODE=oidc` | Expected audience claim. |
| `OIDC_ALGORITHMS` | Optional | Comma-separated list, defaults to `RS256`. |
| `STORAGE_BACKEND` | ✅ | `s3` or `local`. |
| `S3_BUCKET_NAME` | ✅ when using S3 | Bucket where reports are saved. |
| `S3_REPORT_PREFIX` | Optional | Folder prefix inside the bucket (defaults to `reports/`). |
| `LOCAL_STORAGE_PATH` | ✅ when using local storage | Directory for JSON reports. |
| `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | ✅ for S3 (unless using IAM role/profile) | Standard AWS credentials. |
| `TRIVY_BINARY` | Optional | Path to the Trivy executable (defaults to `trivy`). |
| `TRIVY_DEFAULT_MODE` | Optional | Default scan mode (`fs`, `config`, `image`). |
| `TRIVY_SEVERITY` | Optional | Comma-separated severities to include in the report. |
| `TRIVY_FAIL_ON_SEVERITY` | Optional | Comma-separated severities that mark the scan as `failed`. |
| `TRIVY_IGNORE_UNFIXED` | Optional | `true/false`, defaults to `true`. |
| `TRIVY_TIMEOUT_SECONDS` | Optional | Kill the Trivy process if it exceeds this value (default `600`). |
| `TRIVY_ADDITIONAL_ARGS` | Optional | Extra CLI flags appended to every Trivy invocation. |
| `TRIVY_IGNORE_POLICY_PATH` | Optional | Path to a Trivy ignore policy mounted in the container. |
| `TRIVY_CACHE_DIR` | Optional | Shared cache path to speed up DB usage. |
| `MAX_ARCHIVE_SIZE_MB` | Optional | Hard cap on uploaded archive size (default `200`). |
| `ALLOWED_ARCHIVES` | Optional | Comma-separated list of allowed suffixes (default `.tar.gz,.tgz`). |
| `ALLOW_REQUEST_OVERRIDES` | Optional | Allow pipelines to override scan options per request (default `true`). |
| `WEBHOOK_URL` | Optional | Endpoint to notify after each scan (Slack, Teams, etc.). |
| `WEBHOOK_HEADERS` | Optional | Comma-separated `Header:Value` pairs for webhook requests. |
| `AI_REMEDIATION_ENABLED` | Optional | Enable AI summaries (`true/false`). |
| `AI_MODEL_PATH` | ✅ when AI enabled | Path to a `gguf` model consumable by `llama-cpp-python`. |
| `AI_CONTEXT_TOKENS` | Optional | Context window for the AI model (default `2048`). |
| `AI_MAX_OUTPUT_TOKENS` | Optional | Limit for generated text (default `512`). |

### Local Development

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

### Docker Build & Run

```bash
docker build -t trivy-scanner .
docker run -d --rm -p 8000:8000 \
  -e AUTH_MODE=api_key \
  -e SCANNER_API_KEY=super-secret \
  -e STORAGE_BACKEND=s3 \
  -e S3_BUCKET_NAME=your-bucket \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  trivy-scanner
```

### API Contract

`POST /scan-and-store`

- `file` (required): `.tar.gz` or `.tgz` archive.
- Optional form fields (honoured when `ALLOW_REQUEST_OVERRIDES=true`):
  - `scan_mode`, `severity`, `ignore_unfixed`, `fail_on_severity`, `trivy_ignore_policy`.

Successful response:

```json
{
  "status": "completed",
  "report_uri": "s3://bucket/reports/2024-05-20T123456Z-project.json",
  "failed": false,
  "severity_counts": {"CRITICAL": 0, "HIGH": 2, ...},
  "ai_recommendation": "..."  // Present only when AI is enabled and model loaded
}
```

The service sets `failed=true` when any vulnerability matches `TRIVY_FAIL_ON_SEVERITY` (global) or the per-request override.

## Pipeline Integration

### CLI Helper

`tools/trivy_scan_client.py` wraps archive creation, upload, and response handling. It exits with code `2` when the scan reports blocking vulnerabilities so your pipeline can fail fast.

```bash
python tools/trivy_scan_client.py . \
  --api-url "https://scanner.example.com/scan-and-store" \
  --api-key "$SCANNER_API_KEY" \
  --severity "CRITICAL,HIGH" \
  --fail-on "CRITICAL,HIGH" \
  --output scan-report.json
```

### GitHub Actions

See `.github/workflows/trivy-scan.yml` for a reusable job that uploads the JSON report as an artifact. Configure `SCANNER_API_URL` and `SCANNER_API_KEY` as repository secrets.

### Bitbucket Pipelines

The file `examples/bitbucket-pipelines.yml` shows how to call the CLI from Bitbucket. Provide the same environment variables as secured variables in your pipeline settings.

### Other Platforms

- GitLab: add a job that installs `httpx` and runs the CLI.
- Jenkins: use a pipeline stage with the same script, then publish the JSON as a build artifact.
- Self-hosted runners: you can co-locate the scanner container and call `localhost` to avoid egress.

## Webhooks

Set `WEBHOOK_URL` (and optional `WEBHOOK_HEADERS`) to send a JSON payload after every scan. The payload includes overall status, severity counts, report URI, and any AI recommendation string.

```json
{
  "status": "failed",
  "severity_counts": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 5, "LOW": 0, "UNKNOWN": 0},
  "report_uri": "s3://bucket/reports/...",
  "ai_recommendation": "- Update dependency xyz to >=1.2.3"
}
```

## AI Remediation (Optional)

1. Install optional requirements: `pip install -r requirements-ai.txt` (the Docker image can do this as a build-time flag).
2. Download a compatible open-source `gguf` model (e.g. `TheBloke/CodeLlama-7B-Instruct-GGUF` from Hugging Face) and point `AI_MODEL_PATH` to it.
3. Set `AI_REMEDIATION_ENABLED=true`. On each scan the service will summarise the top findings and produce bullet-point mitigation ideas.
4. Treat the output as advisory; automated PR creation should run after human review and regression tests.

## Testing

```
pytest
```

The test suite uses `fastapi.TestClient`, patches the Trivy call, and exercises both success and failure paths so changes to request handling or response structure are caught early.

## Extending Storage or Auth

- Implement a subclass of `StorageProvider` in `app/storage.py` and wire it through `get_storage_provider` to support providers such as Google Cloud Storage or Azure Blob.
- Extend `app/auth.py` with additional strategies (e.g. Bitbucket OAuth, GitHub App tokens) and expose them via the `AUTH_MODE` switch.

## Observability & Next Steps

- Export metrics (e.g. scan duration, vulnerability counts) to Prometheus or StatsD.
- Add structured logging and ship to your log aggregator.
- Bundle the service via Helm/Terraform modules for consistent deployment across platforms.

## Deferred Next Steps

Keep these tasks on the backlog so you can pick them up when ready:

1. Create a fresh virtual environment, install `pip install -r requirements-dev.txt`, and rerun `pytest` (ensure `python-multipart` is installed) to validate the FastAPI changes locally.
2. Build and smoke-test the container locally (`docker build -t trivy-scanner .` followed by `docker run …`) to verify the healthcheck, webhook delivery, and optional AI model wiring in a runtime environment.
3. Configure your pipeline secrets (`SCANNER_API_URL`, `SCANNER_API_KEY`, optional OIDC settings) and enable the provided GitHub Actions or Bitbucket Pipeline job to exercise the new CLI integration end-to-end.
