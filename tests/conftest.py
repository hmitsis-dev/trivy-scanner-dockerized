from __future__ import annotations

import io
import tarfile

import pytest
from fastapi.testclient import TestClient

from trivy_scanner import api
from trivy_scanner.config import Settings


def build_archive(files: dict[str, bytes] | None = None) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for name, content in (files or {"project/app.py": b"print('hello world')\n"}).items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(auth_mode="none", storage_backend="local", local_storage_path=str(tmp_path / "reports"))


@pytest.fixture
def fake_report(monkeypatch):
    """Replace the Trivy subprocess; tests set `.report` and inspect `.calls`."""

    class FakeTrivy:
        report: dict = {"Results": []}
        calls: list = []

        def __call__(self, binary, target, options):
            self.calls.append({"binary": binary, "target": target, "options": options})
            return self.report

    fake = FakeTrivy()
    monkeypatch.setattr(api, "run_trivy_scan", fake)
    return fake


@pytest.fixture
def make_client(settings):
    def _make(**overrides) -> TestClient:
        for key, value in overrides.items():
            setattr(settings, key, value)
        return TestClient(api.create_app(settings))

    return _make
