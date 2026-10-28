from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path

from .config import Settings


class StorageProvider(ABC):
    """Abstract storage provider for scan reports."""

    @abstractmethod
    def store_report(self, key: str, content: dict) -> str:
        """Persist the report and return a URI/identifier."""


class S3StorageProvider(StorageProvider):
    def __init__(self, bucket_name: str, prefix: str = "reports/", s3_client=None) -> None:
        self.bucket_name = bucket_name
        self.prefix = prefix.rstrip("/") + "/" if prefix else ""
        if s3_client is None:
            try:
                import boto3
            except ImportError as exc:  # pragma: no cover - optional dependency
                raise RuntimeError(
                    "S3 storage selected but boto3 is not installed (pip install 'trivy-scanner-api[s3]')"
                ) from exc
            s3_client = boto3.client("s3")
        self.s3_client = s3_client

    def store_report(self, key: str, content: dict) -> str:
        object_key = f"{self.prefix}{key}"
        body = json.dumps(content, indent=2).encode("utf-8")
        self.s3_client.put_object(
            Bucket=self.bucket_name,
            Key=object_key,
            Body=body,
            ContentType="application/json",
        )
        return f"s3://{self.bucket_name}/{object_key}"


class LocalStorageProvider(StorageProvider):
    def __init__(self, base_path: str) -> None:
        self.base_path = Path(base_path).resolve()
        self.base_path.mkdir(parents=True, exist_ok=True)

    def store_report(self, key: str, content: dict) -> str:
        target_path = (self.base_path / key).resolve()
        if not target_path.is_relative_to(self.base_path):
            raise ValueError(f"Refusing to write report outside {self.base_path}: {key}")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
        return str(target_path)


def get_storage_provider(settings: Settings) -> StorageProvider:
    if settings.storage_backend == "s3":
        return S3StorageProvider(bucket_name=settings.s3_bucket_name or "", prefix=settings.s3_prefix)
    if settings.storage_backend == "local":
        return LocalStorageProvider(base_path=settings.local_storage_path)
    raise ValueError(f"Unsupported storage backend: {settings.storage_backend}")
