"""Client for the scanner API, usable as a library or as the `trivy-scan` CLI.

from trivy_scanner.client import ScannerClient

result = ScannerClient("https://scanner.example.com", api_key="...").scan_directory(".")
if result["failed"]:
    ...
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
import tarfile
import tempfile
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import httpx

DEFAULT_EXCLUDES = (".git", "node_modules", "__pycache__", ".venv")
SCAN_ENDPOINT = "/scan-and-store"

EXIT_PASSED = 0
EXIT_ERROR = 1
EXIT_BLOCKING = 2


def _is_excluded(relative: str, patterns: Iterable[str]) -> bool:
    parts = relative.split("/")
    for pattern in patterns:
        pattern = pattern.strip().strip("/")
        if pattern.startswith("./"):
            pattern = pattern[2:]
        if not pattern:
            continue
        if fnmatch.fnmatch(relative, pattern) or any(fnmatch.fnmatch(part, pattern) for part in parts):
            return True
    return False


def create_archive(source: Path, destination: Path, excludes: Iterable[str] = DEFAULT_EXCLUDES) -> Path:
    """Pack `source` into a .tar.gz at `destination`, skipping excluded paths and links."""
    source = Path(source).resolve()
    patterns = list(excludes)

    def _filter(tarinfo: tarfile.TarInfo) -> tarfile.TarInfo | None:
        relative = tarinfo.name.removeprefix(".").lstrip("/")
        if relative and _is_excluded(relative, patterns):
            return None
        # The server rejects links and special files, so leave them out up front.
        if not (tarinfo.isfile() or tarinfo.isdir()):
            return None
        tarinfo.uid = tarinfo.gid = 0
        tarinfo.uname = tarinfo.gname = ""
        return tarinfo

    with tarfile.open(destination, "w:gz") as tar:
        tar.add(source, arcname=".", filter=_filter)
    return destination


def scan_url(api_url: str) -> str:
    """Accept either the service base URL or the full scan endpoint."""
    api_url = api_url.rstrip("/")
    return api_url if api_url.endswith(SCAN_ENDPOINT) else api_url + SCAN_ENDPOINT


def github_oidc_token(audience: str) -> str:
    """Request an OIDC token from the GitHub Actions runtime (needs `permissions: id-token: write`)."""
    request_url = os.getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
    request_token = os.getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not request_url or not request_token:
        raise RuntimeError("GitHub OIDC is unavailable: grant the job `permissions: id-token: write`")
    response = httpx.get(
        request_url,
        params={"audience": audience},
        headers={"Authorization": f"Bearer {request_token}"},
        timeout=30.0,
    )
    response.raise_for_status()
    return response.json()["value"]


class ScannerClient:
    def __init__(
        self,
        api_url: str,
        api_key: str | None = None,
        token: str | None = None,
        timeout: float = 900.0,
        verify: bool = True,
    ) -> None:
        self.url = scan_url(api_url)
        self.headers: dict[str, str] = {}
        if api_key:
            self.headers["X-API-Key"] = api_key
        if token:
            self.headers["Authorization"] = f"Bearer {token}"
        self.timeout = timeout
        self.verify = verify

    def scan_archive(
        self,
        archive: Path,
        scan_mode: str | None = None,
        severity: str | None = None,
        ignore_unfixed: bool | None = None,
        fail_on: str | None = None,
        ignore_policy: str | None = None,
    ) -> dict[str, Any]:
        """Upload an existing .tar.gz archive. `ignore_policy` is the Rego policy text."""
        form: dict[str, str] = {}
        if scan_mode:
            form["scan_mode"] = scan_mode
        if severity:
            form["severity"] = severity
        if ignore_unfixed is not None:
            form["ignore_unfixed"] = str(ignore_unfixed).lower()
        if fail_on:
            form["fail_on_severity"] = fail_on
        if ignore_policy:
            form["trivy_ignore_policy"] = ignore_policy
        with httpx.Client(verify=self.verify, timeout=self.timeout) as client, Path(archive).open("rb") as handle:
            files = {"file": (Path(archive).name, handle, "application/gzip")}
            response = client.post(self.url, headers=self.headers, data=form, files=files)
            response.raise_for_status()
            return response.json()

    def scan_directory(
        self,
        source: Path | str,
        excludes: Iterable[str] = DEFAULT_EXCLUDES,
        **options: Any,
    ) -> dict[str, Any]:
        """Archive a directory, upload it, and return the API response."""
        source = Path(source).resolve()
        if not source.is_dir():
            raise FileNotFoundError(f"Not a directory: {source}")
        with tempfile.TemporaryDirectory() as temp_dir:
            archive = create_archive(source, Path(temp_dir) / f"{source.name or 'project'}.tar.gz", excludes)
            return self.scan_archive(archive, **options)


def _split(values: list[str]) -> list[str]:
    return [item.strip() for value in values for item in value.split(",") if item.strip()]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="trivy-scan",
        description="Upload a project to a Trivy scanner API. Exit codes: 0 passed, 1 error, 2 blocking findings.",
    )
    parser.add_argument("source", type=Path, nargs="?", default=Path("."), help="Directory to scan (default: .)")
    parser.add_argument(
        "--api-url",
        default=os.getenv("SCANNER_API_URL"),
        help="Scanner base URL or /scan-and-store endpoint [env: SCANNER_API_URL]",
    )
    parser.add_argument("--api-key", default=os.getenv("SCANNER_API_KEY"), help="API key [env: SCANNER_API_KEY]")
    parser.add_argument("--token", default=os.getenv("SCANNER_TOKEN"), help="OIDC bearer token [env: SCANNER_TOKEN]")
    parser.add_argument(
        "--github-oidc",
        metavar="AUDIENCE",
        help="Fetch a GitHub Actions OIDC token for this audience and use it as the bearer token",
    )
    parser.add_argument("--severity", help="Comma separated severities to report")
    parser.add_argument("--scan-mode", choices=["fs", "config", "rootfs"], help="Trivy scan mode override")
    parser.set_defaults(ignore_unfixed=None)
    parser.add_argument("--ignore-unfixed", dest="ignore_unfixed", action="store_true", help="Ignore unfixed CVEs")
    parser.add_argument("--no-ignore-unfixed", dest="ignore_unfixed", action="store_false", help="Include unfixed CVEs")
    parser.add_argument("--fail-on", help="Comma separated severities that should fail the pipeline")
    parser.add_argument("--ignore-policy", type=Path, help="Local Rego ignore policy file to send with the request")
    parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        help=f"Glob(s) to exclude, comma separated or repeated (added to: {', '.join(DEFAULT_EXCLUDES)})",
    )
    parser.add_argument("--no-default-excludes", action="store_true", help="Do not apply the default excludes")
    parser.add_argument("--timeout", type=float, default=900.0, help="Request timeout in seconds (default: 900)")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification")
    parser.add_argument("--output", type=Path, help="Write the JSON response to this file")
    parser.add_argument("--quiet", action="store_true", help="Do not print the JSON response")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.api_url:
        parser.error("--api-url (or SCANNER_API_URL) is required")
    if not args.source.is_dir():
        parser.error(f"Source directory does not exist: {args.source}")

    excludes = ([] if args.no_default_excludes else list(DEFAULT_EXCLUDES)) + _split(args.exclude)
    output = args.output.resolve() if args.output else None
    if output and output.is_relative_to(args.source.resolve()):
        # Do not upload a previous run's report.
        excludes.append(output.relative_to(args.source.resolve()).as_posix())

    try:
        token = github_oidc_token(args.github_oidc) if args.github_oidc else args.token
        client = ScannerClient(args.api_url, args.api_key, token, timeout=args.timeout, verify=not args.insecure)
        payload = client.scan_directory(
            args.source,
            excludes=excludes,
            scan_mode=args.scan_mode,
            severity=args.severity,
            ignore_unfixed=args.ignore_unfixed,
            fail_on=args.fail_on,
            ignore_policy=args.ignore_policy.read_text(encoding="utf-8") if args.ignore_policy else None,
        )
    except httpx.HTTPStatusError as exc:
        print(f"Scan request failed: {exc.response.status_code} {exc.response.text}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:  # pylint: disable=broad-except
        print(f"Scan request failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    rendered = json.dumps(payload, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
    if not args.quiet:
        print(rendered)
    counts = payload.get("severity_counts") or {}
    print("Findings: " + ", ".join(f"{name}={count}" for name, count in counts.items()), file=sys.stderr)
    if payload.get("failed"):
        print("Scan reported blocking findings", file=sys.stderr)
        return EXIT_BLOCKING
    return EXIT_PASSED


if __name__ == "__main__":
    sys.exit(main())
