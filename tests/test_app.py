import io
import os
import sys
import tarfile
from pathlib import Path
from typing import Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("STORAGE_BACKEND", "local")
os.environ.setdefault("LOCAL_STORAGE_PATH", "./.test-reports")
os.environ.setdefault("AUTH_MODE", "none")
os.environ.setdefault("ALLOW_REQUEST_OVERRIDES", "true")
os.environ.setdefault("TRIVY_DEFAULT_MODE", "fs")
os.environ.setdefault("TRIVY_SEVERITY", "CRITICAL,HIGH")

from fastapi.testclient import TestClient  # noqa: E402

from app import main as app_main  # noqa: E402
from app.config import settings  # noqa: E402


client = TestClient(app_main.app)


def _build_archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        content = b"print('hello world')\n"
        info = tarfile.TarInfo(name="project/app.py")
        info.size = len(content)
        tar.addfile(info, io.BytesIO(content))
    buffer.seek(0)
    return buffer.read()


def test_scan_success(monkeypatch):
    archive = _build_archive()
    sample_report: Dict = {
        "Results": [
            {
                "Target": "project/app.py",
                "Vulnerabilities": [],
            }
        ]
    }

    def fake_scan(*_, **__):
        return sample_report

    monkeypatch.setattr(app_main, "run_trivy_scan", fake_scan)

    response = client.post(
        "/scan-and-store",
        files={"file": ("project.tar.gz", archive, "application/gzip")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["failed"] is False
    assert payload["severity_counts"]["CRITICAL"] == 0


def test_scan_failure_flag(monkeypatch):
    archive = _build_archive()
    vulnerable_report: Dict = {
        "Results": [
            {
                "Target": "project/app.py",
                "Vulnerabilities": [
                    {"VulnerabilityID": "CVE-123", "Severity": "HIGH", "Description": "demo"}
                ],
            }
        ]
    }

    def fake_scan(*_, **__):
        return vulnerable_report

    monkeypatch.setattr(app_main, "run_trivy_scan", fake_scan)
    monkeypatch.setattr(settings, "trivy_fail_on_severity", ["HIGH"])

    response = client.post(
        "/scan-and-store",
        files={"file": ("project.tar.gz", archive, "application/gzip")},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["failed"] is True
    assert payload["severity_counts"]["HIGH"] == 1
