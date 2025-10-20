import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


logger = logging.getLogger(__name__)


@dataclass
class ScanOptions:
    mode: str
    severity: List[str]
    ignore_unfixed: bool
    fail_on_severity: List[str]
    additional_args: List[str] = field(default_factory=list)
    timeout: int = 600
    cache_dir: Optional[str] = None
    ignore_policy: Optional[str] = None

    def as_command(self, trivy_binary: str, target: Path) -> List[str]:
        command = [trivy_binary, self.mode, str(target), "--format", "json"]
        if self.severity:
            command.extend(["--severity", ",".join(self.severity)])
        if self.ignore_unfixed:
            command.append("--ignore-unfixed")
        if self.ignore_policy:
            command.extend(["--ignore-policy", self.ignore_policy])
        command.extend(self.additional_args)
        return command


def run_trivy_scan(trivy_binary: str, temp_dir: Path, options: ScanOptions) -> Dict:
    command = options.as_command(trivy_binary, temp_dir)
    env = os.environ.copy()
    if options.cache_dir:
        env["TRIVY_CACHE_DIR"] = options.cache_dir
    logger.info("Executing Trivy command: %s", " ".join(command))
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            cwd=temp_dir,
            timeout=options.timeout,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        logger.error("Trivy scan timed out after %s seconds", options.timeout)
        raise RuntimeError(f"Trivy scan timed out after {options.timeout} seconds") from exc
    if process.returncode != 0:
        logger.error("Trivy failed with code %s: %s", process.returncode, process.stderr)
        raise RuntimeError(f"Trivy failed (code {process.returncode}): {process.stderr}")
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON output from Trivy: %s", exc)
        raise RuntimeError("Failed to parse Trivy output as JSON") from exc


def should_fail(report: Dict, fail_levels: List[str]) -> bool:
    if not fail_levels:
        return False
    fail_set = set(level.upper() for level in fail_levels)
    for result in report.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            if vuln.get("Severity", "").upper() in fail_set:
                return True
    return False
