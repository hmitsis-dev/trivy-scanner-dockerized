from __future__ import annotations

import hmac
from collections.abc import Callable
from typing import Any

import httpx
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from .config import Settings

Identity = dict[str, Any]

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
_bearer = HTTPBearer(auto_error=False)


def _unauthorized(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


class APIKeyAuth:
    def __init__(self, api_key: str) -> None:
        self._api_key = api_key.encode()

    def __call__(self, api_key: str | None = Security(_api_key_header)) -> Identity:
        if not api_key or not hmac.compare_digest(api_key.encode(), self._api_key):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key")
        return {"sub": "api-key-client"}


class OIDCAuth:
    """Validates bearer JWTs against the issuer's published signing keys."""

    def __init__(
        self,
        issuer: str,
        audience: str,
        algorithms: list[str],
        required_claims: dict[str, str] | None = None,
    ) -> None:
        try:
            import jwt  # noqa: F401
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "OIDC authentication requested but PyJWT is not installed (pip install 'trivy-scanner-api[oidc]')"
            ) from exc
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.algorithms = algorithms
        self.required_claims = required_claims or {}
        self._jwks_client = None

    def _discover_jwks_uri(self) -> str:
        response = httpx.get(f"{self.issuer}/.well-known/openid-configuration", timeout=10.0)
        response.raise_for_status()
        return response.json()["jwks_uri"]

    def _get_jwks_client(self):
        if self._jwks_client is None:
            import jwt

            # PyJWKClient caches keys and refetches when it sees an unknown kid.
            self._jwks_client = jwt.PyJWKClient(self._discover_jwks_uri(), cache_keys=True, lifespan=3600)
        return self._jwks_client

    def verify(self, token: str) -> Identity:
        import jwt

        try:
            signing_key = self._get_jwks_client().get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=self.algorithms,
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
        except (jwt.PyJWTError, httpx.HTTPError, KeyError) as exc:
            raise _unauthorized(f"Invalid token: {exc}") from exc
        for claim, expected in self.required_claims.items():
            if str(claims.get(claim)) != expected:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Claim '{claim}' not allowed")
        return claims

    def __call__(self, credentials: HTTPAuthorizationCredentials | None = Security(_bearer)) -> Identity:
        if not credentials:
            raise _unauthorized("Missing bearer token")
        return self.verify(credentials.credentials)


def build_auth_dependency(settings: Settings) -> Callable[..., Identity]:
    if settings.auth_mode == "none":

        def allow_all() -> Identity:
            return {"sub": "anonymous"}

        return allow_all
    if settings.auth_mode == "api_key":
        return APIKeyAuth(settings.api_key or "")
    if settings.auth_mode == "oidc":
        return OIDCAuth(
            settings.oidc_issuer or "",
            settings.oidc_audience or "",
            settings.oidc_algorithms,
            settings.oidc_required_claims,
        )
    raise ValueError(f"Unsupported AUTH_MODE: {settings.auth_mode}")
