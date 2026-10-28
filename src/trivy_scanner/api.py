from __future__ import annotations

import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, status

from . import __version__
from .ai import AIClient
from .archive import ArchiveValidationError, copy_with_limit, ensure_allowed_extension, safe_extract_tar, safe_filename
from .auth import build_auth_dependency
from .config import Settings
from .scanner import ScanOptions, ScanOptionsError, count_severities, run_trivy_scan, should_fail
from .storage import StorageProvider, get_storage_provider
from .webhooks import send_webhook

logger = logging.getLogger(__name__)


def create_app(
    settings: Settings | None = None,
    storage: StorageProvider | None = None,
    ai_client: AIClient | None = None,
) -> FastAPI:
    """Build the scanner API. Without arguments, configuration is read from the environment."""
    settings = settings or Settings.from_env()
    storage = storage or get_storage_provider(settings)
    auth_dependency = build_auth_dependency(settings)
    if ai_client is None and settings.ai_enabled:
        try:
            ai_client = AIClient(settings)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("AI remediation disabled: %s", exc)

    app = FastAPI(title="Trivy Scanner API", version=__version__)
    app.state.settings = settings

    # Declared sync so FastAPI runs it in a worker thread: Trivy is a blocking subprocess.
    @app.post("/scan-and-store")
    def scan_and_store(
        file: UploadFile = File(...),
        scan_mode: str | None = Form(None),
        severity: str | None = Form(None),
        ignore_unfixed: str | None = Form(None),
        fail_on_severity: str | None = Form(None),
        trivy_ignore_policy: str | None = Form(None),
        identity: dict[str, Any] = Depends(auth_dependency),
    ) -> dict[str, Any]:
        try:
            filename = safe_filename(file.filename or "")
            ensure_allowed_extension(filename, settings.allowed_archives)
        except ArchiveValidationError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        logger.info("Received scan request for %s from %s", filename, identity.get("sub"))

        overrides = settings.allow_request_overrides

        try:
            options = ScanOptions(
                mode=scan_mode.strip().lower() if overrides and scan_mode else settings.trivy_default_mode,
                severity=_parse_csv(severity) if overrides and severity else settings.trivy_severity,
                ignore_unfixed=(
                    _parse_bool(ignore_unfixed)
                    if overrides and ignore_unfixed is not None
                    else settings.trivy_ignore_unfixed
                ),
                fail_on_severity=(
                    _parse_csv(fail_on_severity) if overrides and fail_on_severity else settings.trivy_fail_on_severity
                ),
                additional_args=settings.trivy_additional_args,
                timeout=settings.trivy_timeout,
                cache_dir=settings.trivy_cache_dir,
                ignore_policy=settings.trivy_ignore_policy_path,
            )
        except ScanOptionsError as exc:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                archive_path = temp_path / filename
                copy_with_limit(file.file, archive_path, settings.max_archive_size_mb)
                workspace_dir = temp_path / "workspace"
                workspace_dir.mkdir()
                safe_extract_tar(
                    archive_path,
                    workspace_dir,
                    max_members=settings.max_archive_members,
                    max_extracted_mb=settings.max_extracted_size_mb,
                )
                if overrides and trivy_ignore_policy:
                    policy_path = temp_path / "ignore-policy.rego"
                    policy_path.write_text(trivy_ignore_policy, encoding="utf-8")
                    options.ignore_policy = str(policy_path)

                report = run_trivy_scan(settings.trivy_binary, workspace_dir, options)
        except ArchiveValidationError as exc:
            logger.warning("Invalid archive: %s", exc)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            logger.error("Trivy binary not found: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Trivy binary not found"
            ) from exc
        except RuntimeError as exc:
            logger.error("Trivy scan failed: %s", exc)
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc

        failed = should_fail(report, options.fail_on_severity)
        enriched_report = _decorate_report(report, options, failed, identity)
        report_uri = storage.store_report(_build_report_key(filename), enriched_report)

        remediation = None
        if ai_client:
            try:
                remediation = ai_client.generate_remediation(report)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("AI remediation failed: %s", exc)

        counts = count_severities(report)
        summary: dict[str, Any] = {
            "status": "failed" if failed else "passed",
            "severity_counts": counts,
            "report_uri": report_uri,
        }
        if remediation:
            summary["ai_recommendation"] = remediation
        try:
            send_webhook(settings.webhook_url, summary, settings.webhook_headers)
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Webhook delivery failed: %s", exc)

        response: dict[str, Any] = {
            "status": "completed",
            "report_uri": report_uri,
            "failed": failed,
            "severity_counts": counts,
            "ai_recommendation": remediation,
        }
        if failed:
            response["message"] = "Failing due to configured severity threshold"
        return response

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    return app


def _parse_csv(items: str) -> list[str]:
    return [item.strip() for item in items.split(",") if item.strip()]


def _parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "t", "yes", "y"}


def _build_report_key(filename: str) -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%S%fZ")
    stem = filename.removesuffix(".tar.gz").removesuffix(".tgz")
    return f"{timestamp}-{stem}.json"


def _decorate_report(report: dict, options: ScanOptions, failed: bool, identity: dict) -> dict:
    return {
        **report,
        "scanner_metadata": {
            "failed": failed,
            "scan_mode": options.mode,
            "severity_filter": options.severity,
            "ignore_unfixed": options.ignore_unfixed,
            "requested_by": identity.get("sub"),
            "scanner_version": __version__,
        },
    }
