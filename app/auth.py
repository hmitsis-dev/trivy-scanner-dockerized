import time
from typing import Any, Dict

import httpx
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

try:
    from jose import JWTError, jwk, jwt
    from jose.utils import base64url_decode
except ImportError:  # pragma: no cover - optional dependency
    JWTError = jwk = jwt = None  # type: ignore
    base64url_decode = None  # type: ignore

from .config import settings


class APIKeyAuth:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.header = APIKeyHeader(name="X-API-Key", auto_error=False)

    async def __call__(self, api_key: str = Security(APIKeyHeader(name="X-API-Key", auto_error=False))):
        if not api_key or api_key != self.api_key:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API key")
        return {"sub": "api-key-client"}


class OIDCAuth:
    def __init__(self, issuer: str, audience: str, algorithms: list[str]) -> None:
        if JWTError is None or base64url_decode is None:
            raise RuntimeError(
                "OIDC authentication requested but python-jose[cryptography] is not installed"
            )
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.algorithms = algorithms
        self.jwks_url = f"{self.issuer}/.well-known/jwks.json"
        self._jwks: Dict[str, Any] | None = None
        self._jwks_expiry = 0.0
        self.http = httpx.Client(timeout=10.0)
        self.bearer = HTTPBearer(auto_error=False)

    def _refresh_jwks(self) -> None:
        response = self.http.get(self.jwks_url)
        response.raise_for_status()
        payload = response.json()
        keys = payload.get("keys")
        if not keys:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="JWKS response missing keys")
        self._jwks = {key["kid"]: key for key in keys if "kid" in key}
        self._jwks_expiry = time.time() + 3600

    def _get_key(self, kid: str) -> Dict[str, Any]:
        if not self._jwks or time.time() > self._jwks_expiry:
            self._refresh_jwks()
        assert self._jwks is not None
        key = self._jwks.get(kid)
        if not key:
            # Refresh once more in case of rotation
            self._refresh_jwks()
            key = self._jwks.get(kid)
        if not key:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unknown signing key")
        return key

    async def __call__(self, credentials: HTTPAuthorizationCredentials = Security(HTTPBearer(auto_error=False))):
        if not credentials:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
        token = credentials.credentials
        try:
            header = jwt.get_unverified_header(token)
        except JWTError as exc:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token header: {exc}") from exc
        kid = header.get("kid")
        if not kid:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing kid")
        key_dict = self._get_key(kid)
        try:
            public_key = jwk.construct(key_dict)
            message, encoded_signature = token.rsplit(".", 1)
            decoded_signature = base64url_decode(encoded_signature.encode())
            if not public_key.verify(message.encode(), decoded_signature):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token signature invalid")
            claims = jwt.get_unverified_claims(token)
            if claims.get("iss") != self.issuer:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid issuer")
            audience = claims.get("aud")
            if isinstance(audience, list):
                if self.audience not in audience:
                    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid audience")
            elif audience != self.audience:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid audience")
            exp = claims.get("exp")
            if exp and time.time() > exp:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")
        except HTTPException:
            raise
        except Exception as exc:  # pylint: disable=broad-except
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Token validation error: {exc}") from exc
        return claims


def get_auth_dependency():
    if settings.auth_mode == "none":
        async def allow_all():
            return {"sub": "anonymous"}
        return allow_all
    if settings.auth_mode == "api_key":
        return APIKeyAuth(settings.api_key)
    if settings.auth_mode == "oidc":
        return OIDCAuth(settings.oidc_issuer, settings.oidc_audience, settings.oidc_algorithms)
    raise ValueError(f"Unsupported AUTH_MODE: {settings.auth_mode}")
