"""Tests for the ``/.well-known`` routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.fastapi.dependencies import config
from gafaelfawr.util import number_to_base64
from tests.support.app import create_fastapi_test_app, create_test_client

if TYPE_CHECKING:
    from pathlib import Path


async def test_well_known_jwks(tmp_path: Path) -> None:
    app = await create_fastapi_test_app(tmp_path)

    async with create_test_client(app) as client:
        r = await client.get("/.well-known/jwks.json")
        assert r.status_code == 200
        result = r.json()

    keypair = config().issuer.keypair
    assert result == {
        "keys": [
            {
                "alg": ALGORITHM,
                "kty": "RSA",
                "use": "sig",
                "n": number_to_base64(keypair.public_numbers().n).decode(),
                "e": number_to_base64(keypair.public_numbers().e).decode(),
                "kid": "some-kid",
            }
        ],
    }

    # Ensure that we didn't add padding to the key components.  Stripping the
    # padding is required by RFC 7515 and 7518.
    assert "=" not in result["keys"][0]["n"]
    assert "=" not in result["keys"][0]["e"]


async def test_well_known_oidc(tmp_path: Path) -> None:
    app = await create_fastapi_test_app(tmp_path)

    async with create_test_client(app) as client:
        r = await client.get("/.well-known/openid-configuration")
        assert r.status_code == 200
        result = r.json()

    base_url = config().issuer.iss
    assert result == {
        "issuer": config().issuer.iss,
        "authorization_endpoint": base_url + "/auth/openid/login",
        "token_endpoint": base_url + "/auth/openid/token",
        "userinfo_endpoint": base_url + "/auth/userinfo",
        "jwks_uri": base_url + "/.well-known/jwks.json",
        "scopes_supported": ["openid"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [ALGORITHM],
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }
