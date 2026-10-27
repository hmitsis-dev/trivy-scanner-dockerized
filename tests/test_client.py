import tarfile

import httpx
import pytest

from trivy_scanner import client as client_module
from trivy_scanner.client import ScannerClient, create_archive, scan_url


def _tree(tmp_path):
    src = tmp_path / "proj"
    (src / ".git").mkdir(parents=True)
    (src / ".git" / "config").write_text("x")
    (src / ".github").mkdir()
    (src / ".github" / "ci.yml").write_text("x")
    (src / "node_modules" / "lib").mkdir(parents=True)
    (src / "node_modules" / "lib" / "i.js").write_text("x")
    (src / "dist").mkdir()
    (src / "dist" / "bundle.js").write_text("x")
    (src / "app.py").write_text("print(1)")
    (src / "link").symlink_to(src / "app.py")
    return src


def _names(archive):
    with tarfile.open(archive) as tar:
        return {m.name for m in tar.getmembers()}


def test_create_archive_excludes(tmp_path):
    src = _tree(tmp_path)
    names = _names(create_archive(src, tmp_path / "a.tar.gz", [".git", "node_modules", "dist"]))
    assert "./app.py" in names
    assert "./.github/ci.yml" in names
    assert not any(n.startswith(("./.git/", "./node_modules", "./dist")) for n in names)
    assert "./link" not in names


def test_scan_url():
    assert scan_url("https://x.example.com") == "https://x.example.com/scan-and-store"
    assert scan_url("https://x.example.com/scan-and-store/") == "https://x.example.com/scan-and-store"


def _mock_transport(monkeypatch, handler):
    real_client = httpx.Client

    def patched(*args, **kwargs):
        kwargs["transport"] = httpx.MockTransport(handler)
        return real_client(*args, **kwargs)

    monkeypatch.setattr(client_module.httpx, "Client", patched)


def test_scan_directory_sends_auth_and_form(tmp_path, monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["headers"] = request.headers
        seen["body"] = request.read()
        return httpx.Response(200, json={"failed": False, "severity_counts": {}})

    _mock_transport(monkeypatch, handler)
    result = ScannerClient("https://scanner", api_key="k", token="t").scan_directory(
        _tree(tmp_path), fail_on="CRITICAL"
    )
    assert result["failed"] is False
    assert seen["headers"]["x-api-key"] == "k"
    assert seen["headers"]["authorization"] == "Bearer t"
    assert b'name="fail_on_severity"' in seen["body"]


@pytest.mark.parametrize("failed,code", [(False, 0), (True, 2)])
def test_cli_exit_codes(tmp_path, monkeypatch, failed, code):
    _mock_transport(monkeypatch, lambda r: httpx.Response(200, json={"failed": failed, "severity_counts": {"HIGH": 1}}))
    out = tmp_path / "proj" / "report.json"
    assert client_module.main([str(_tree(tmp_path)), "--api-url", "https://s", "--output", str(out), "--quiet"]) == code
    assert out.exists()


def test_cli_http_error(tmp_path, monkeypatch):
    _mock_transport(monkeypatch, lambda r: httpx.Response(403, json={"detail": "Invalid API key"}))
    assert client_module.main([str(_tree(tmp_path)), "--api-url", "https://s"]) == 1
