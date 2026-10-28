# Trivy Scanner API

> Self-hosted Trivy scanning as a service: one HTTP endpoint for every CI pipeline in your organization, plus a small client to call it.

[![CI](https://github.com/hmitsis-dev/trivy-scanner-dockerized/actions/workflows/ci.yml/badge.svg)](https://github.com/hmitsis-dev/trivy-scanner-dockerized/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Most teams install Trivy in every CI job, scatter results across pipeline logs, and never build a consistent audit trail. This project runs Trivy behind a FastAPI service that any pipeline can reach over HTTP. Upload an archive, get back severity counts and a pass/fail verdict, and let the service handle report storage, alerting, and (optionally) AI remediation hints.

It ships as three things:

| Piece | What it is | Get it |
|-------|------------|--------|
| **Server** | FastAPI service wrapping a pinned Trivy binary | `docker run ghcr.io/hmitsis-dev/trivy-scanner-dockerized` or `pip install "trivy-scanner-api[server]"` |
| **Client** | `trivy-scan` CLI and `ScannerClient` Python class (only depends on `httpx`) | `pip install trivy-scanner-api` |
| **GitHub Action** | Wraps the client, supports keyless OIDC auth | `uses: hmitsis-dev/trivy-scanner-dockerized@v2` |

```
  CI pipeline ── trivy-scan ──►  POST /scan-and-store  (tar.gz + options, API key or OIDC token)
                                        │
                     ┌──────────────────┴──────────────────┐
                     │ 1. authenticate                      │
                     │ 2. validate + safely extract archive │
                     │ 3. run Trivy (fs / config / rootfs)  │
                     │ 4. apply fail-on thresholds          │
                     │ 5. store report (local disk or S3)   │
                     │ 6. notify webhook (Slack / Teams)    │
                     │ 7. AI remediation (optional)         │
                     └──────────────────────────────────────┘
```

## When to use this (and when not to)

Trivy already has good options of its own. Pick the simplest one that covers your needs.

| You want | Use |
|----------|-----|
| Scan in a single GitHub repo | [`aquasecurity/trivy-action`](https://github.com/aquasecurity/trivy-action) |
| One shared vulnerability DB and Trivy version across runners | Trivy's built-in [client/server mode](https://trivy.dev/latest/docs/references/modes/client-server/) (`trivy server` + `trivy fs --server ...`) |
| Dashboards, triage and finding history across many projects | [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) or [Dependency-Track](https://dependencytrack.org/) |
| One endpoint that applies the same fail-on rules everywhere, stores every report, sends a webhook, and accepts keyless GitHub OIDC, with no Trivy install in the pipeline | **This project** |

The trade-off: the pipeline uploads its source tree to the scanner. Trivy's client/server mode sends only package metadata. If uploading source is unacceptable in your environment, use that instead. This project also doesn't provide a UI or history queries; reports are plain JSON files on disk or in S3, which you can feed into the tools above.

## Quick start

```bash
# 1. Run the server (reports land in a Docker volume)
docker run -d -p 8000:8000 \
  -e SCANNER_API_KEY=dev-secret \
  -v trivy-cache:/var/cache/trivy \
  ghcr.io/hmitsis-dev/trivy-scanner-dockerized:latest

# 2. Install the client and scan the current directory
pip install trivy-scanner-api
trivy-scan . --api-url http://localhost:8000 --api-key dev-secret --fail-on CRITICAL,HIGH
```

Exit codes: `0` passed, `1` request error, `2` blocking findings.

> Until the first release is published to GHCR/PyPI, build from a checkout instead:
> `docker build -t trivy-scanner .` and `pip install .`

`examples/docker-compose.yml` shows a persistent deployment with named volumes for reports and the Trivy DB cache.

## Using it from CI

### GitHub Actions

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write   # only for OIDC
    steps:
      - uses: actions/checkout@v4
      - uses: hmitsis-dev/trivy-scanner-dockerized@v2
        with:
          api-url: ${{ vars.SCANNER_API_URL }}
          api-key: ${{ secrets.SCANNER_API_KEY }}   # or: oidc-audience: trivy-scanner
          fail-on: CRITICAL,HIGH
```

Inputs: `api-url`, `api-key`, `oidc-audience`, `path`, `severity`, `fail-on`, `scan-mode`, `exclude`, `output` (default `scan-report.json`). See `examples/github-actions.yml`.

### GitLab, Bitbucket, Jenkins, anything else

```bash
pip install trivy-scanner-api
export SCANNER_API_URL=https://scanner.example.com SCANNER_API_KEY=...
trivy-scan . --fail-on CRITICAL,HIGH --output scan-report.json
```

Ready-made configs: `examples/gitlab-ci.yml`, `examples/bitbucket-pipelines.yml`.

### CLI reference

```
trivy-scan [SOURCE] [--api-url URL] [--api-key KEY | --token JWT | --github-oidc AUDIENCE]
           [--severity LIST] [--fail-on LIST] [--scan-mode fs|config|rootfs]
           [--ignore-unfixed | --no-ignore-unfixed] [--ignore-policy FILE.rego]
           [--exclude GLOBS] [--no-default-excludes] [--timeout SECONDS]
           [--output FILE] [--quiet] [--insecure]
```

`--api-url`, `--api-key` and `--token` fall back to `SCANNER_API_URL`, `SCANNER_API_KEY` and `SCANNER_TOKEN`. `.git`, `node_modules`, `__pycache__` and `.venv` are excluded by default; symlinks are never uploaded.

### Python API

```python
from trivy_scanner.client import ScannerClient

client = ScannerClient("https://scanner.example.com", api_key="...")
result = client.scan_directory(".", fail_on="CRITICAL", severity="CRITICAL,HIGH,MEDIUM")
print(result["severity_counts"], result["report_uri"])
```

The server is also embeddable: `trivy_scanner.api.create_app(settings, storage=...)` returns a FastAPI app, so you can mount it in another service or pass your own `StorageProvider`.

## Authentication

| `AUTH_MODE` | Configure | Client sends |
|-------------|-----------|--------------|
| `api_key` (default) | `SCANNER_API_KEY` | `X-API-Key` header (`--api-key`) |
| `oidc` | `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_REQUIRED_CLAIMS` | `Authorization: Bearer` (`--token` / `--github-oidc`) |
| `none` | nothing | nothing; only for private networks |

OIDC keys are discovered through the issuer's `/.well-known/openid-configuration`, cached, and refreshed on key rotation. Tokens must carry valid `iss`, `aud` and `exp`.

**Keyless GitHub Actions:** set

```
AUTH_MODE=oidc
OIDC_ISSUER=https://token.actions.githubusercontent.com
OIDC_AUDIENCE=trivy-scanner
OIDC_REQUIRED_CLAIMS=repository_owner=your-org
```

and use `oidc-audience: trivy-scanner` in the action. `OIDC_REQUIRED_CLAIMS` is mandatory for the GitHub issuer: any public repository can mint a token for any audience, so without it every GitHub user could use your scanner. Restrict further with e.g. `repository=your-org/app,ref=refs/heads/main`.

## Configuration

All server settings are environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_MODE` | `api_key` | `api_key`, `oidc` or `none` |
| `SCANNER_API_KEY` | — | Required for `api_key` mode |
| `OIDC_ISSUER` / `OIDC_AUDIENCE` | — | Required for `oidc` mode |
| `OIDC_ALGORITHMS` | `RS256` | Accepted signing algorithms |
| `OIDC_REQUIRED_CLAIMS` | — | `claim=value` pairs, comma separated, all must match |
| `STORAGE_BACKEND` | `local` | `local` or `s3` |
| `LOCAL_STORAGE_PATH` | `./reports` (`/data/reports` in Docker) | Report directory |
| `S3_BUCKET_NAME` | — | Required for `s3`; credentials come from the standard AWS chain (env, profile, IAM role) |
| `S3_REPORT_PREFIX` | `reports/` | Key prefix inside the bucket |
| `TRIVY_BINARY` | `trivy` | Path to the Trivy executable |
| `TRIVY_DEFAULT_MODE` | `fs` | `fs`, `config` or `rootfs` |
| `TRIVY_SEVERITY` | `CRITICAL,HIGH` | Severities included in the report |
| `TRIVY_FAIL_ON_SEVERITY` | — | Severities that set `failed: true` |
| `TRIVY_IGNORE_UNFIXED` | `true` | Skip vulnerabilities without a fix |
| `TRIVY_TIMEOUT_SECONDS` | `600` | Kill Trivy after this long |
| `TRIVY_ADDITIONAL_ARGS` | — | Extra flags for every run, comma separated |
| `TRIVY_IGNORE_POLICY_PATH` | — | Server-side Rego ignore policy |
| `TRIVY_CACHE_DIR` | `/var/cache/trivy` in Docker | Vulnerability DB cache; mount a volume to keep it |
| `ALLOW_REQUEST_OVERRIDES` | `true` | Let clients override mode, severities and ignore policy |
| `MAX_ARCHIVE_SIZE_MB` | `200` | Upload size limit |
| `MAX_EXTRACTED_SIZE_MB` | `1024` | Limit on total extracted size |
| `MAX_ARCHIVE_MEMBERS` | `10000` | Limit on files per archive |
| `ALLOWED_ARCHIVES` | `.tar.gz,.tgz` | Accepted extensions |
| `WEBHOOK_URL` | — | Called after every scan |
| `WEBHOOK_HEADERS` | — | `Header:Value` pairs, comma separated |
| `AI_REMEDIATION_ENABLED` | `false` | Enable AI hints (needs the `ai` extra) |
| `AI_MODEL_PATH` | — | Path to a `.gguf` model |
| `AI_CONTEXT_TOKENS` / `AI_MAX_OUTPUT_TOKENS` / `AI_TEMPERATURE` | `2048` / `512` / `0.2` | Model settings |
| `HOST` / `PORT` / `LOG_LEVEL` | `0.0.0.0` / `8000` / `info` | `trivy-scanner-server` bind and logging |

`TRIVY_SEVERITY` controls what Trivy reports; `TRIVY_FAIL_ON_SEVERITY` controls what fails the pipeline. You can report everything and only block on `CRITICAL`.

## API

### `POST /scan-and-store`

`multipart/form-data` fields:

| Field | Required | Description |
|-------|----------|-------------|
| `file` | yes | `.tar.gz` / `.tgz` archive |
| `scan_mode` | no | `fs`, `config` or `rootfs` |
| `severity` | no | Comma separated severities to report |
| `ignore_unfixed` | no | `true` / `false` |
| `fail_on_severity` | no | Comma separated severities that set `failed` |
| `trivy_ignore_policy` | no | Rego ignore policy **contents** |

```json
{
  "status": "completed",
  "failed": true,
  "message": "Failing due to configured severity threshold",
  "report_uri": "/data/reports/2026-10-27T120000123456Z-project.json",
  "severity_counts": {"CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0},
  "ai_recommendation": null
}
```

Counts and the `failed` verdict cover vulnerabilities, failed misconfigurations and secrets. The stored report is Trivy's full JSON plus a `scanner_metadata` block (mode, filters, verdict, requester identity). Interactive docs are at `/docs`.

### `GET /healthz`

`{"status": "ok", "version": "..."}`. Used by the image's `HEALTHCHECK`.

### Webhook payload

```json
{
  "text": "Trivy scan failed (CRITICAL: 1, HIGH: 3, ...). Report: s3://bucket/reports/....json",
  "status": "failed",
  "severity_counts": {"CRITICAL": 1, "HIGH": 3, "MEDIUM": 5, "LOW": 0, "UNKNOWN": 0},
  "report_uri": "s3://bucket/reports/....json"
}
```

The `text` field makes it work with Slack and Teams incoming webhooks as-is.

## Security model

Uploaded archives are untrusted input. Before Trivy sees them the server:

- strips directory components from the upload filename;
- streams the upload to disk and stops once it passes `MAX_ARCHIVE_SIZE_MB`;
- rejects archives with too many members, more than `MAX_EXTRACTED_SIZE_MB` of content, paths that escape the extraction directory, links, or device files;
- extracts with Python's `data` filter into a temporary directory that is removed after the request;
- validates scan mode and severities against allow-lists before building the Trivy command (no shell involved).

The container runs as an unprivileged user, and the Trivy release tarball is checked against its published SHA-256 checksums at build time. API keys are compared in constant time.

## AI remediation (optional)

1. `pip install "trivy-scanner-api[server,ai]"` (or extend the image).
2. Download a GGUF instruction model, e.g. a Q4_K_M 7B model (about 5 GB RAM).
3. Set `AI_REMEDIATION_ENABLED=true` and `AI_MODEL_PATH=/models/model.gguf`.

The model loads once at startup and gets the top 10 findings per scan. Nothing leaves your infrastructure. Treat the output as a hint, not a fix.

## Extending

**Storage backend:** subclass `trivy_scanner.storage.StorageProvider` and pass it to `create_app`:

```python
import json

from trivy_scanner.api import create_app
from trivy_scanner.storage import StorageProvider

class GCSStorage(StorageProvider):
    def __init__(self, bucket):
        self.bucket = bucket

    def store_report(self, key, content):
        self.bucket.blob(key).upload_from_string(json.dumps(content), content_type="application/json")
        return f"gs://{self.bucket.name}/{key}"

app = create_app(storage=GCSStorage(bucket))
```

**Auth strategy:** add a callable to `trivy_scanner/auth.py` and select it in `build_auth_dependency`. It must work as a FastAPI dependency and return a dict with at least `sub`.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
ruff check . && ruff format --check .

# run the server locally (needs trivy on PATH)
AUTH_MODE=none trivy-scanner-server
```

CI runs lint and tests on Python 3.10–3.13, then builds the image and scans this repository through it. Pushing a `v*` tag publishes the multi-arch image to GHCR and the package to PyPI.

## License

[MIT](LICENSE)
