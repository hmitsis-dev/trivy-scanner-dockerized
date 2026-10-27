import json
from pathlib import Path

from conftest import build_archive


def _post(client, archive=None, filename="project.tar.gz", **form):
    return client.post(
        "/scan-and-store",
        files={"file": (filename, archive or build_archive(), "application/gzip")},
        data=form,
    )


def test_healthz(make_client):
    response = make_client().get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_scan_success_stores_report(make_client, fake_report):
    response = _post(make_client())
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "completed"
    assert payload["failed"] is False
    assert payload["severity_counts"]["CRITICAL"] == 0
    stored = json.loads(Path(payload["report_uri"]).read_text())
    assert stored["scanner_metadata"]["requested_by"] == "anonymous"


def test_scan_failure_flag(make_client, fake_report):
    fake_report.report = {
        "Results": [
            {
                "Target": "project/app.py",
                "Vulnerabilities": [{"VulnerabilityID": "CVE-123", "Severity": "HIGH"}],
            }
        ]
    }
    payload = _post(make_client(trivy_fail_on_severity=["HIGH"])).json()
    assert payload["failed"] is True
    assert payload["severity_counts"]["HIGH"] == 1


def test_misconfigurations_and_secrets_count(make_client, fake_report):
    fake_report.report = {
        "Results": [
            {
                "Target": "Dockerfile",
                "Misconfigurations": [
                    {"ID": "DS002", "Severity": "HIGH", "Status": "FAIL"},
                    {"ID": "DS001", "Severity": "HIGH", "Status": "PASS"},
                ],
                "Secrets": [{"RuleID": "aws-key", "Severity": "CRITICAL"}],
            }
        ]
    }
    payload = _post(make_client(), fail_on_severity="CRITICAL").json()
    assert payload["severity_counts"]["HIGH"] == 1
    assert payload["severity_counts"]["CRITICAL"] == 1
    assert payload["failed"] is True


def test_request_overrides_are_applied(make_client, fake_report):
    _post(make_client(), scan_mode="config", severity="low,medium", ignore_unfixed="false")
    options = fake_report.calls[-1]["options"]
    assert options.mode == "config"
    assert options.severity == ["LOW", "MEDIUM"]
    assert options.ignore_unfixed is False


def test_request_overrides_can_be_disabled(make_client, fake_report):
    _post(make_client(allow_request_overrides=False), scan_mode="config")
    assert fake_report.calls[-1]["options"].mode == "fs"


def test_inline_ignore_policy_written_to_temp_file(make_client, monkeypatch):
    seen = {}

    def capture(binary, target, options):
        seen["policy"] = Path(options.ignore_policy).read_text()
        return {"Results": []}

    monkeypatch.setattr("trivy_scanner.api.run_trivy_scan", capture)
    assert _post(make_client(), trivy_ignore_policy="package trivy\ndefault ignore = false\n").status_code == 200
    assert seen["policy"].startswith("package trivy")


def test_invalid_scan_mode_rejected(make_client, fake_report):
    response = _post(make_client(), scan_mode="--output=/etc/passwd")
    assert response.status_code == 400


def test_invalid_severity_rejected(make_client, fake_report):
    assert _post(make_client(), severity="HIGH,BOGUS").status_code == 400


def test_wrong_extension_rejected(make_client, fake_report):
    assert _post(make_client(), filename="project.zip").status_code == 400


def test_filename_path_traversal_is_neutralised(make_client, fake_report, settings):
    response = _post(make_client(), filename="../../../evil.tar.gz")
    assert response.status_code == 200
    report_path = Path(response.json()["report_uri"])
    assert report_path.parent == Path(settings.local_storage_path).resolve()
    assert report_path.name.endswith("-evil.json")


def test_oversized_upload_rejected(make_client, fake_report):
    response = _post(make_client(max_archive_size_mb=0), archive=build_archive())
    assert response.status_code == 400


def test_api_key_required(make_client, fake_report):
    client = make_client(auth_mode="api_key", api_key="s3cret")
    assert _post(client).status_code == 403
    response = client.post(
        "/scan-and-store",
        headers={"X-API-Key": "s3cret"},
        files={"file": ("project.tar.gz", build_archive(), "application/gzip")},
    )
    assert response.status_code == 200


def test_webhook_receives_slack_compatible_payload(make_client, fake_report, monkeypatch):
    sent = {}

    def fake_send(url, payload, headers=None):
        sent.update(url=url, payload=payload, headers=headers)

    monkeypatch.setattr("trivy_scanner.api.send_webhook", fake_send)
    _post(make_client(webhook_url="https://hooks.example.com/x", webhook_headers={"Authorization": "Bearer t"}))
    assert sent["url"] == "https://hooks.example.com/x"
    assert sent["payload"]["status"] == "passed"
    assert sent["headers"] == {"Authorization": "Bearer t"}
