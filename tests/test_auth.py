import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from trivy_scanner.auth import OIDCAuth
from trivy_scanner.config import GITHUB_ACTIONS_ISSUER, Settings

ISSUER = "https://issuer.example.com"


@pytest.fixture(scope="module")
def private_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def oidc(private_key):
    auth = OIDCAuth(ISSUER, "trivy-scanner", ["RS256"], {"repository_owner": "my-org"})

    class StaticJWKS:
        def get_signing_key_from_jwt(self, token):
            return jwt.PyJWK.from_dict(
                {**jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True), "kid": "k1"}
            )

    auth._jwks_client = StaticJWKS()
    return auth


def _token(private_key, **claims):
    base = {"iss": ISSUER, "aud": "trivy-scanner", "exp": int(time.time()) + 60, "repository_owner": "my-org"}
    base.update(claims)
    return jwt.encode(base, private_key, algorithm="RS256", headers={"kid": "k1"})


def test_valid_token(oidc, private_key):
    claims = oidc.verify(_token(private_key, sub="repo:my-org/app:ref:refs/heads/main"))
    assert claims["sub"].startswith("repo:my-org")


@pytest.mark.parametrize(
    "claims,status",
    [
        ({"aud": "someone-else"}, 401),
        ({"iss": "https://evil.example.com"}, 401),
        ({"exp": int(time.time()) - 10}, 401),
        ({"repository_owner": "other-org"}, 403),
    ],
)
def test_invalid_tokens(oidc, private_key, claims, status):
    with pytest.raises(HTTPException) as exc:
        oidc.verify(_token(private_key, **claims))
    assert exc.value.status_code == status


def test_token_signed_by_other_key(oidc):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(HTTPException) as exc:
        oidc.verify(_token(other))
    assert exc.value.status_code == 401


def test_github_oidc_requires_claim_restriction():
    settings = Settings(auth_mode="oidc", oidc_issuer=GITHUB_ACTIONS_ISSUER, oidc_audience="x")
    with pytest.raises(ValueError, match="OIDC_REQUIRED_CLAIMS"):
        settings.validate()


def test_settings_from_env_parses_pairs():
    settings = Settings.from_env(
        {
            "AUTH_MODE": "none",
            "WEBHOOK_HEADERS": "Authorization:Bearer abc, X-Team: sec",
            "TRIVY_FAIL_ON_SEVERITY": "CRITICAL,HIGH",
        }
    )
    assert settings.webhook_headers == {"Authorization": "Bearer abc", "X-Team": "sec"}
    assert settings.trivy_fail_on_severity == ["CRITICAL", "HIGH"]
    assert settings.storage_backend == "local"
