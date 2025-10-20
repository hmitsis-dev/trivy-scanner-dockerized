from __future__ import annotations

import logging
import shutil
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, status

from .ai import get_ai_client
from .auth import get_auth_dependency
from .config import settings
from .scanner import ScanOptions, run_trivy_scan, should_fail
from .storage import get_storage_provider
from .utils import ArchiveValidationError, ensure_allowed_extension, ensure_file_size_within_limit, safe_extract_tar
from .webhooks import send_webhook

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI(title="Trivy Scanner API", version="2.0.0")
_auth_dependency = get_auth_dependency()
storage_provider = get_storage_provider(settings)
ai_client = None
try:
    ai_client = get_ai_client()
except Exception as exc:  # pylint: disable=broad-except
    logger.warning("AI remediation disabled: %s", exc)
    ai_client = None


@app.post("/scan-and-store")
async def scan_and_store(
    file: UploadFile = File(...),
    scan_mode: Optional[str] = Form(None),
    severity: Optional[str] = Form(None),
    ignore_unfixed: Optional[str] = Form(None),
    fail_on_severity: Optional[str] = Form(None),
    trivy_ignore_policy: Optional[str] = Form(None),
    identity: Dict = Depends(_auth_dependency),
):
    logger.info("Received scan request for %s from %s", file.filename, identity.get("sub"))
    ensure_allowed_extension(file.filename, settings.allowed_archives)

    overrides_allowed = settings.allow_request_overrides

    scan_options = ScanOptions(
        mode=(scan_mode if overrides_allowed and scan_mode else settings.trivy_default_mode),
        severity=(_parse_csv(severity) if overrides_allowed and severity else settings.trivy_severity),
        ignore_unfixed=(
            _parse_bool(ignore_unfixed)
            if overrides_allowed and ignore_unfixed is not None
            else settings.trivy_ignore_unfixed
        ),
        fail_on_severity=(
            _parse_csv(fail_on_severity)
            if overrides_allowed and fail_on_severity
            else settings.trivy_fail_on_severity
        ),
        additional_args=settings.trivy_additional_args,
        timeout=settings.trivy_timeout,
        cache_dir=settings.trivy_cache_dir,
        ignore_policy=(
            trivy_ignore_policy
            if overrides_allowed and trivy_ignore_policy
            else settings.trivy_ignore_policy_path
        ),
    )

    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            archive_path = temp_path / file.filename
            with archive_path.open("wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            ensure_file_size_within_limit(archive_path, settings.max_archive_size_mb)
            workspace_dir = temp_path / "workspace"
            workspace_dir.mkdir(parents=True, exist_ok=True)
            safe_extract_tar(archive_path, workspace_dir)

            report = run_trivy_scan(settings.trivy_binary, workspace_dir, scan_options)
            failed = should_fail(report, scan_options.fail_on_severity)
            report_key = _build_report_key(file.filename)
            enriched_report = _decorate_report(report, scan_options, failed, identity)
            report_uri = storage_provider.store_report(report_key, enriched_report)
            remediation = None
            if ai_client:
                try:
                    remediation = ai_client.generate_remediation(report)
                except Exception as exc:  # pylint: disable=broad-except
                    logger.warning("AI remediation failed: %s", exc)
            summary = _build_summary(report, failed, report_uri, remediation)
            try:
                send_webhook(summary)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("Webhook delivery failed: %s", exc)
    except ArchiveValidationError as exc:
        logger.error("Invalid archive: %s", exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        logger.error("Trivy binary not found: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Trivy binary not found") from exc
    except RuntimeError as exc:
        logger.error("Trivy scan failed: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    except Exception as exc:  # pylint: disable=broad-except
        logger.exception("Unexpected error during scan")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

    response = {
        "status": "completed",
        "report_uri": report_uri,
        "failed": failed,
        "severity_counts": summary["severity_counts"],
        "ai_recommendation": remediation,
    }
    if failed:
        response["message"] = "Failing due to configured severity threshold"
    return response


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


def _parse_csv(items: str) -> list[str]:
    return [item.strip() for item in items.split(",") if item.strip()]


def _parse_bool(value: Optional[str]) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"1", "true", "t", "yes", "y"}


def _build_report_key(filename: str) -> str:
    timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H%M%SZ")
    safe_name = filename.replace(".tar.gz", "").replace(".tgz", "")
    return f"{timestamp}-{safe_name}.json"


def _decorate_report(report: Dict, options: ScanOptions, failed: bool, identity: Dict) -> Dict:
    report_copy = {**report}
    report_copy["scanner_metadata"] = {
        "failed": failed,
        "scan_mode": options.mode,
        "severity_filter": options.severity,
        "ignore_unfixed": options.ignore_unfixed,
        "requested_by": identity.get("sub"),
    }
    return report_copy


def _build_summary(report: Dict, failed: bool, uri: str, remediation: Optional[str]) -> Dict:
    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            severity = (vuln.get("Severity") or "UNKNOWN").upper()
            if severity not in counts:
                counts[severity] = 0
            counts[severity] += 1
    summary = {
        "status": "failed" if failed else "passed",
        "severity_counts": counts,
        "report_uri": uri,
    }
    if remediation:
        summary["ai_recommendation"] = remediation
    return summary
