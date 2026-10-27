from __future__ import annotations

import json
import logging
import os
import subprocess
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
# Modes that scan a directory tree, which is what an uploaded archive becomes.
SCAN_MODES = ("fs", "config", "rootfs")


class ScanOptionsError(ValueError):
    """Raised when scan options contain unsupported values."""


def normalize_severities(values: list[str]) -> list[str]:
    normalized = [value.strip().upper() for value in values if value.strip()]
    unknown = [value for value in normalized if value not in SEVERITIES]
    if unknown:
        raise ScanOptionsError(f"Unknown severities: {', '.join(unknown)}. Allowed: {', '.join(SEVERITIES)}")
    return normalized


@dataclass
class ScanOptions:
    mode: str
    severity: list[str]
    ignore_unfixed: bool
    fail_on_severity: list[str]
    additional_args: list[str] = field(default_factory=list)
    timeout: int = 600
    cache_dir: str | None = None
    ignore_policy: str | None = None

    def __post_init__(self) -> None:
        if self.mode not in SCAN_MODES:
            raise ScanOptionsError(f"Unsupported scan mode {self.mode!r}. Allowed: {', '.join(SCAN_MODES)}")
        self.severity = normalize_severities(self.severity)
        self.fail_on_severity = normalize_severities(self.fail_on_severity)

    def as_command(self, trivy_binary: str, target: Path) -> list[str]:
        command = [trivy_binary, self.mode, "--format", "json", "--quiet"]
        if self.severity:
            command.extend(["--severity", ",".join(self.severity)])
        if self.ignore_unfixed:
            command.append("--ignore-unfixed")
        if self.ignore_policy:
            command.extend(["--ignore-policy", self.ignore_policy])
        command.extend(self.additional_args)
        command.append(str(target))
        return command


def run_trivy_scan(trivy_binary: str, target: Path, options: ScanOptions) -> dict:
    command = options.as_command(trivy_binary, target)
    env = os.environ.copy()
    if options.cache_dir:
        env["TRIVY_CACHE_DIR"] = options.cache_dir
    logger.info("Executing Trivy command: %s", " ".join(command))
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=target,
            timeout=options.timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Trivy scan timed out after {options.timeout} seconds") from exc
    if process.returncode != 0:
        raise RuntimeError(f"Trivy failed (code {process.returncode}): {process.stderr.strip()}")
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Failed to parse Trivy output as JSON") from exc


def iter_findings(report: dict) -> Iterator[dict]:
    """Yield every vulnerability, failed misconfiguration and secret in a Trivy report."""
    for result in report.get("Results") or []:
        target = result.get("Target", "unknown")
        for vuln in result.get("Vulnerabilities") or []:
            yield {"kind": "vulnerability", "target": target, **vuln}
        for misconfig in result.get("Misconfigurations") or []:
            if misconfig.get("Status", "FAIL") == "FAIL":
                yield {"kind": "misconfiguration", "target": target, **misconfig}
        for secret in result.get("Secrets") or []:
            yield {"kind": "secret", "target": target, **secret}


def _severity(finding: dict) -> str:
    severity = (finding.get("Severity") or "UNKNOWN").upper()
    return severity if severity in SEVERITIES else "UNKNOWN"


def count_severities(report: dict) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for finding in iter_findings(report):
        counts[_severity(finding)] += 1
    return counts


def should_fail(report: dict, fail_levels: list[str]) -> bool:
    if not fail_levels:
        return False
    fail_set = {level.upper() for level in fail_levels}
    return any(_severity(finding) in fail_set for finding in iter_findings(report))
