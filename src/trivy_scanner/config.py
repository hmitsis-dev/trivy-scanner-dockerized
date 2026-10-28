from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"


def _as_bool(value: str | None, default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "t", "yes", "y"}


def _as_list(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _as_pairs(value: str | None, separator: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for item in _as_list(value):
        if separator not in item:
            raise ValueError(f"Expected '<key>{separator}<value>', got: {item!r}")
        key, val = item.split(separator, 1)
        pairs[key.strip()] = val.strip()
    return pairs


@dataclass
class Settings:
    auth_mode: str = "api_key"
    api_key: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_algorithms: list[str] = field(default_factory=lambda: ["RS256"])
    oidc_required_claims: dict[str, str] = field(default_factory=dict)

    storage_backend: str = "local"
    s3_bucket_name: str | None = None
    s3_prefix: str = "reports/"
    local_storage_path: str = "./reports"

    webhook_url: str | None = None
    webhook_headers: dict[str, str] = field(default_factory=dict)

    trivy_binary: str = "trivy"
    trivy_default_mode: str = "fs"
    trivy_severity: list[str] = field(default_factory=lambda: ["CRITICAL", "HIGH"])
    trivy_ignore_unfixed: bool = True
    trivy_fail_on_severity: list[str] = field(default_factory=list)
    trivy_timeout: int = 600
    trivy_additional_args: list[str] = field(default_factory=list)
    trivy_cache_dir: str | None = None
    trivy_ignore_policy_path: str | None = None

    allow_request_overrides: bool = True

    max_archive_size_mb: int = 200
    max_extracted_size_mb: int = 1024
    max_archive_members: int = 10_000
    allowed_archives: list[str] = field(default_factory=lambda: [".tar.gz", ".tgz"])

    ai_enabled: bool = False
    ai_model_path: str | None = None
    ai_context_tokens: int = 2048
    ai_temperature: float = 0.2
    ai_max_output_tokens: int = 512

    def validate(self) -> None:
        if self.storage_backend not in {"s3", "local"}:
            raise ValueError(f"Unsupported STORAGE_BACKEND: {self.storage_backend}")
        if self.storage_backend == "s3" and not self.s3_bucket_name:
            raise ValueError("S3 storage selected but S3_BUCKET_NAME is not set")
        if self.storage_backend == "local" and not self.local_storage_path:
            raise ValueError("Local storage selected but LOCAL_STORAGE_PATH is not set")

        if self.auth_mode not in {"api_key", "oidc", "none"}:
            raise ValueError(f"Unsupported AUTH_MODE: {self.auth_mode}")
        if self.auth_mode == "api_key" and not self.api_key:
            raise ValueError("API key authentication selected but SCANNER_API_KEY is missing")
        if self.auth_mode == "oidc":
            if not self.oidc_issuer or not self.oidc_audience:
                raise ValueError("OIDC authentication requires OIDC_ISSUER and OIDC_AUDIENCE")
            if not self.oidc_algorithms:
                raise ValueError("OIDC_ALGORITHMS must include at least one algorithm")
            # Any public GitHub repository can mint a token for any audience, so
            # the issuer alone does not identify *your* pipelines.
            if self.oidc_issuer.rstrip("/") == GITHUB_ACTIONS_ISSUER and not self.oidc_required_claims:
                raise ValueError(
                    "GitHub Actions OIDC requires OIDC_REQUIRED_CLAIMS "
                    "(e.g. repository_owner=my-org) so other repositories cannot use this scanner"
                )
        if self.ai_enabled and not self.ai_model_path:
            raise ValueError("AI remediation enabled but AI_MODEL_PATH is not set")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env
        settings = cls(
            auth_mode=env.get("AUTH_MODE", "api_key").strip().lower(),
            api_key=env.get("SCANNER_API_KEY"),
            oidc_issuer=env.get("OIDC_ISSUER"),
            oidc_audience=env.get("OIDC_AUDIENCE"),
            oidc_algorithms=_as_list(env.get("OIDC_ALGORITHMS")) or ["RS256"],
            oidc_required_claims=_as_pairs(env.get("OIDC_REQUIRED_CLAIMS"), "="),
            storage_backend=env.get("STORAGE_BACKEND", "local").strip().lower(),
            s3_bucket_name=env.get("S3_BUCKET_NAME"),
            s3_prefix=env.get("S3_REPORT_PREFIX", "reports/").strip(),
            local_storage_path=env.get("LOCAL_STORAGE_PATH", "./reports"),
            webhook_url=env.get("WEBHOOK_URL"),
            webhook_headers=_as_pairs(env.get("WEBHOOK_HEADERS"), ":"),
            trivy_binary=env.get("TRIVY_BINARY", "trivy"),
            trivy_default_mode=env.get("TRIVY_DEFAULT_MODE", "fs").strip().lower(),
            trivy_severity=_as_list(env.get("TRIVY_SEVERITY")) or ["CRITICAL", "HIGH"],
            trivy_ignore_unfixed=_as_bool(env.get("TRIVY_IGNORE_UNFIXED"), True),
            trivy_fail_on_severity=_as_list(env.get("TRIVY_FAIL_ON_SEVERITY")),
            trivy_timeout=int(env.get("TRIVY_TIMEOUT_SECONDS", "600")),
            trivy_additional_args=_as_list(env.get("TRIVY_ADDITIONAL_ARGS")),
            trivy_cache_dir=env.get("TRIVY_CACHE_DIR"),
            trivy_ignore_policy_path=env.get("TRIVY_IGNORE_POLICY_PATH"),
            allow_request_overrides=_as_bool(env.get("ALLOW_REQUEST_OVERRIDES"), True),
            max_archive_size_mb=int(env.get("MAX_ARCHIVE_SIZE_MB", "200")),
            max_extracted_size_mb=int(env.get("MAX_EXTRACTED_SIZE_MB", "1024")),
            max_archive_members=int(env.get("MAX_ARCHIVE_MEMBERS", "10000")),
            allowed_archives=_as_list(env.get("ALLOWED_ARCHIVES")) or [".tar.gz", ".tgz"],
            ai_enabled=_as_bool(env.get("AI_REMEDIATION_ENABLED"), False),
            ai_model_path=env.get("AI_MODEL_PATH"),
            ai_context_tokens=int(env.get("AI_CONTEXT_TOKENS", "2048")),
            ai_temperature=float(env.get("AI_TEMPERATURE", "0.2")),
            ai_max_output_tokens=int(env.get("AI_MAX_OUTPUT_TOKENS", "512")),
        )
        settings.validate()
        return settings
