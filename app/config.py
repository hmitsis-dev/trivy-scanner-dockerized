import os
from dataclasses import dataclass, field
from typing import List, Optional


def _as_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "t", "yes", "y"}


def _as_list(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass
class Settings:
    api_key: Optional[str]
    auth_mode: str
    oidc_issuer: Optional[str]
    oidc_audience: Optional[str]
    oidc_algorithms: List[str]

    storage_backend: str
    s3_bucket_name: Optional[str]
    s3_prefix: str
    local_storage_path: str

    webhook_url: Optional[str]
    webhook_headers: List[str]

    trivy_binary: str
    trivy_default_mode: str
    trivy_severity: List[str]
    trivy_ignore_unfixed: bool
    trivy_fail_on_severity: List[str]
    trivy_timeout: int
    trivy_additional_args: List[str]
    trivy_cache_dir: Optional[str]
    trivy_ignore_policy_path: Optional[str]

    allow_request_overrides: bool

    max_archive_size_mb: int
    allowed_archives: List[str]

    ai_enabled: bool
    ai_model_path: Optional[str]
    ai_context_tokens: int
    ai_temperature: float
    ai_max_output_tokens: int

    def validate(self) -> None:
        if self.storage_backend == "s3" and not self.s3_bucket_name:
            raise ValueError("S3 storage selected but S3_BUCKET_NAME is not set")
        if self.storage_backend == "s3" and not any(
            os.getenv(key) for key in ("AWS_ACCESS_KEY_ID", "AWS_PROFILE", "AWS_ROLE_ARN")
        ):
            raise ValueError(
                "S3 storage selected but no AWS authentication method detected (set AWS_ACCESS_KEY_ID/SECRET, AWS_PROFILE, or AWS_ROLE_ARN)"
            )
        if os.getenv("AWS_ACCESS_KEY_ID") and not os.getenv("AWS_SECRET_ACCESS_KEY"):
            raise ValueError("AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is missing")
        if self.storage_backend == "local" and not self.local_storage_path:
            raise ValueError("Local storage selected but LOCAL_STORAGE_PATH is not set")

        if self.auth_mode == "api_key" and not self.api_key:
            raise ValueError("API key authentication selected but SCANNER_API_KEY is missing")
        if self.auth_mode == "oidc":
            if not self.oidc_issuer or not self.oidc_audience:
                raise ValueError("OIDC authentication requires OIDC_ISSUER and OIDC_AUDIENCE")
            if not self.oidc_algorithms:
                raise ValueError("OIDC_ALGORITHMS must include at least one algorithm")
        if self.ai_enabled and not self.ai_model_path:
            raise ValueError("AI remediation enabled but AI_MODEL_PATH is not set")

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            api_key=os.getenv("SCANNER_API_KEY"),
            auth_mode=os.getenv("AUTH_MODE", "api_key").strip().lower(),
            oidc_issuer=os.getenv("OIDC_ISSUER"),
            oidc_audience=os.getenv("OIDC_AUDIENCE"),
            oidc_algorithms=_as_list(os.getenv("OIDC_ALGORITHMS")) or ["RS256"],
            storage_backend=os.getenv("STORAGE_BACKEND", "s3").strip().lower(),
            s3_bucket_name=os.getenv("S3_BUCKET_NAME"),
            s3_prefix=os.getenv("S3_REPORT_PREFIX", "reports/").strip(),
            local_storage_path=os.getenv("LOCAL_STORAGE_PATH", "./reports"),
            webhook_url=os.getenv("WEBHOOK_URL"),
            webhook_headers=_as_list(os.getenv("WEBHOOK_HEADERS")),
            trivy_binary=os.getenv("TRIVY_BINARY", "trivy"),
            trivy_default_mode=os.getenv("TRIVY_DEFAULT_MODE", "fs"),
            trivy_severity=_as_list(os.getenv("TRIVY_SEVERITY")) or ["CRITICAL", "HIGH"],
            trivy_ignore_unfixed=_as_bool(os.getenv("TRIVY_IGNORE_UNFIXED"), True),
            trivy_fail_on_severity=_as_list(os.getenv("TRIVY_FAIL_ON_SEVERITY")),
            trivy_timeout=int(os.getenv("TRIVY_TIMEOUT_SECONDS", "600")),
            trivy_additional_args=_as_list(os.getenv("TRIVY_ADDITIONAL_ARGS")),
            trivy_cache_dir=os.getenv("TRIVY_CACHE_DIR"),
            trivy_ignore_policy_path=os.getenv("TRIVY_IGNORE_POLICY_PATH"),
            allow_request_overrides=_as_bool(os.getenv("ALLOW_REQUEST_OVERRIDES"), True),
            max_archive_size_mb=int(os.getenv("MAX_ARCHIVE_SIZE_MB", "200")),
            allowed_archives=_as_list(os.getenv("ALLOWED_ARCHIVES")) or [".tar.gz", ".tgz"],
            ai_enabled=_as_bool(os.getenv("AI_REMEDIATION_ENABLED"), False),
            ai_model_path=os.getenv("AI_MODEL_PATH"),
            ai_context_tokens=int(os.getenv("AI_CONTEXT_TOKENS", "2048")),
            ai_temperature=float(os.getenv("AI_TEMPERATURE", "0.2")),
            ai_max_output_tokens=int(os.getenv("AI_MAX_OUTPUT_TOKENS", "512")),
        )
        settings.validate()
        return settings


settings = Settings.from_env()
