#!/usr/bin/env python3
"""Command line helper to package a repository and call the scanner API."""

from __future__ import annotations

import argparse
import json
import os
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Dict

import httpx


def create_archive(source: Path, excludes: list[str]) -> Path:
    temp_dir = Path(tempfile.mkdtemp())
    archive_path = temp_dir / f"{source.name}.tar.gz"
    patterns = [pattern.lstrip("./") for pattern in excludes]

    def _filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
        relative = Path(tarinfo.name.lstrip("./"))
        for pattern in patterns:
            if relative.match(pattern) or str(relative).startswith(f"{pattern}/"):
                return None
        return tarinfo

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(source, arcname=".", filter=_filter)
    return archive_path


def request_scan(
    api_url: str,
    api_key: str | None,
    archive: Path,
    form: Dict[str, str],
    verify_ssl: bool,
) -> httpx.Response:
    headers = {}
    if api_key:
        headers["X-API-Key"] = api_key
    with httpx.Client(verify=verify_ssl, timeout=120.0) as client:
        with archive.open("rb") as handle:
            files = {"file": (archive.name, handle, "application/gzip")}
            response = client.post(api_url, headers=headers, data=form, files=files)
            response.raise_for_status()
            return response


def parse_overrides(args: argparse.Namespace) -> Dict[str, str]:
    overrides: Dict[str, str] = {}
    if args.scan_mode:
        overrides["scan_mode"] = args.scan_mode
    if args.severity:
        overrides["severity"] = args.severity
    if args.ignore_unfixed is not None:
        overrides["ignore_unfixed"] = str(args.ignore_unfixed).lower()
    if args.fail_on:
        overrides["fail_on_severity"] = args.fail_on
    if args.ignore_policy:
        overrides["trivy_ignore_policy"] = args.ignore_policy
    return overrides


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload a project archive to the Trivy scanner API")
    parser.add_argument("source", type=Path, help="Path to the project to archive")
    parser.add_argument("--api-url", required=True, help="Scanner API endpoint (e.g. https://host/scan-and-store)")
    parser.add_argument("--api-key", help="API key for authentication")
    parser.add_argument("--severity", help="Comma separated severity levels to include")
    parser.add_argument("--scan-mode", help="Trivy scan mode override (fs, config, image)")
    parser.set_defaults(ignore_unfixed=None)
    parser.add_argument("--ignore-unfixed", dest="ignore_unfixed", action="store_true", help="Ignore unfixed vulnerabilities")
    parser.add_argument("--no-ignore-unfixed", dest="ignore_unfixed", action="store_false", help="Include unfixed vulnerabilities")
    parser.add_argument("--fail-on", help="Comma separated severities that should fail the pipeline")
    parser.add_argument("--ignore-policy", help="Path to a Trivy ignore policy file uploaded with the request")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[".git", "node_modules", "__pycache__"],
        help="Glob patterns to exclude from the archive",
    )
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--output", help="Write the JSON response to the specified file")
    args = parser.parse_args()

    source = args.source.resolve()
    if not source.exists():
        parser.error(f"Source path does not exist: {source}")
    archive = create_archive(source, args.exclude)
    overrides = parse_overrides(args)

    try:
        response = request_scan(args.api_url, args.api_key, archive, overrides, not args.insecure)
    except httpx.HTTPStatusError as exc:
        print(f"Scan request failed: {exc.response.status_code} {exc.response.text}", file=sys.stderr)
        return 1
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Scan request failed: {exc}", file=sys.stderr)
        return 1

    payload = response.json()
    if args.output:
        Path(args.output).write_text(response.text, encoding="utf-8")
    print(json.dumps(payload, indent=2))
    if payload.get("failed"):
        print("Scan reported blocking vulnerabilities", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
