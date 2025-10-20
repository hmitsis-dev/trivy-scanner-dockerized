import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict

import boto3


class StorageProvider(ABC):
    """Abstract storage provider for scan reports."""

    @abstractmethod
    def store_report(self, key: str, content: Dict) -> str:
        """Persist the report and return a URI/identifier."""


class S3StorageProvider(StorageProvider):
    def __init__(self, bucket_name: str, prefix: str = "reports/", s3_client=None) -> None:
        self.bucket_name = bucket_name
        self.prefix = prefix.rstrip("/") + "/" if prefix else ""
        self.s3_client = s3_client or boto3.client("s3")

    def store_report(self, key: str, content: Dict) -> str:
        object_key = f"{self.prefix}{key}" if self.prefix else key
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
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)

    def store_report(self, key: str, content: Dict) -> str:
        target_path = self.base_path / key
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(json.dumps(content, indent=2), encoding="utf-8")
        return str(target_path.resolve())


def get_storage_provider(config) -> StorageProvider:
    if config.storage_backend == "s3":
        return S3StorageProvider(bucket_name=config.s3_bucket_name, prefix=config.s3_prefix)
    if config.storage_backend == "local":
        return LocalStorageProvider(base_path=config.local_storage_path)
    raise ValueError(f"Unsupported storage backend: {config.storage_backend}")
