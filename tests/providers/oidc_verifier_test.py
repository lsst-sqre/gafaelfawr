"""Tests for verification of upstream OpenID Connect token verification."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

import jwt
import pytest
import respx
from _pytest._code import ExceptionInfo
from jwt.exceptions import InvalidIssuerError
from safir.datetime import current_datetime

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.exceptions import (
    FetchKeysError,
    ProviderWebError,
    UnknownAlgorithmError,
    UnknownKeyIdError,
)
from gafaelfawr.factory import Factory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.models.oidc import OIDCToken

from ..support.config import reconfigure
from ..support.constants import TEST_KEYPAIR
from ..support.jwt import create_upstream_oidc_jwt
from ..support.oidc import mock_oidc_provider_config


def encode_token(
    payload: dict[str, Any], keypair: RSAKeyPair, kid: str | None = None
) -> OIDCToken:
    """Encode a token payload into a token manually."""
    headers = {}
    if kid:
        headers["kid"] = kid
    encoded = jwt.encode(
        payload,
        keypair.private_key_as_pem().decode(),
        algorithm=ALGORITHM,
        headers=headers,
    )
    return OIDCToken(encoded=encoded)


@pytest.mark.asyncio
async def test_verify_token(
    tmp_path: Path, respx_mock: respx.Router, factory: Factory
) -> None:
    config = await reconfigure(tmp_path, "oidc", factory)
    assert config.oidc
    verifier = factory.create_oidc_token_verifier()

    now = current_datetime()
    exp = now + timedelta(days=24)
    payload: dict[str, Any] = {
        "aud": config.oidc.audience,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    token = encode_token(payload, TEST_KEYPAIR)
    excinfo: ExceptionInfo[Exception]

    # Missing iss.
    with pytest.raises(InvalidIssuerError) as excinfo:
        await verifier.verify_token(token)
    assert str(excinfo.value) == "No iss claim in token"

    # Missing kid.
    payload["iss"] = "https://bogus.example.com/"
    token = encode_token(payload, TEST_KEYPAIR)
    with pytest.raises(UnknownKeyIdError) as excinfo:
        await verifier.verify_token(token)
    assert str(excinfo.value) == "No kid in token header"

    # Unknown issuer.
    token = encode_token(payload, TEST_KEYPAIR, kid="a-kid")
    with pytest.raises(InvalidIssuerError) as excinfo:
        await verifier.verify_token(token)
    assert str(excinfo.value) == "Unknown issuer: https://bogus.example.com/"


@pytest.mark.asyncio
async def test_verify_no_kids(
    tmp_path: Path, respx_mock: respx.Router, factory: Factory
) -> None:
    config = await reconfigure(tmp_path, "oidc-no-kids", factory)
    assert config.oidc
    verifier = factory.create_oidc_token_verifier()
    await mock_oidc_provider_config(respx_mock, "kid")

    now = current_datetime()
    exp = now + timedelta(days=24)
    payload: dict[str, Any] = {
        "aud": config.oidc.audience,
        "iat": int(now.timestamp()),
        "iss": config.oidc.issuer,
        "exp": int(exp.timestamp()),
    }
    token = encode_token(payload, TEST_KEYPAIR, kid="a-kid")
    with pytest.raises(UnknownKeyIdError) as excinfo:
        await verifier.verify_token(token)
    expected = f"Issuer {config.oidc.issuer} has no kid a-kid"
    assert str(excinfo.value) == expected


@pytest.mark.asyncio
async def test_key_retrieval(
    tmp_path: Path, respx_mock: respx.Router, factory: Factory
) -> None:
    config = await reconfigure(tmp_path, "oidc-no-kids", factory)
    assert config.oidc
    verifier = factory.create_oidc_token_verifier()

    # Initial working JWKS configuration.
    jwks = TEST_KEYPAIR.public_key_as_jwks("some-kid")

    # Register that handler at the well-known JWKS endpoint.  This will return
    # a connection refused from the OpenID Connect endpoint.
    jwks_url = urljoin(config.oidc.issuer, "/.well-known/jwks.json")
    oidc_url = urljoin(config.oidc.issuer, "/.well-known/openid-configuration")
    respx_mock.get(jwks_url).respond(json=jwks.model_dump())
    respx_mock.get(oidc_url).respond(404)

    # Check token verification with this configuration.
    token = create_upstream_oidc_jwt("some-user", kid="some-kid")
    assert await verifier.verify_token(token)

    # Wrong algorithm for the key.
    jwks.keys[0].alg = "ES256"
    respx_mock.get(jwks_url).respond(json=jwks.model_dump())
    with pytest.raises(UnknownAlgorithmError):
        await verifier.verify_token(token)

    # Should go back to working if we fix the algorithm and add more keys.
    # Add an explicit 404 from the OpenID connect endpoint.
    respx_mock.get(oidc_url).respond(404)
    jwks.keys[0].alg = ALGORITHM
    keypair = RSAKeyPair.generate()
    jwks.keys.insert(0, keypair.public_key_as_jwks("a-kid").keys[0])
    respx_mock.get(jwks_url).respond(json=jwks.model_dump())
    assert await verifier.verify_token(token)

    # Try with a new key ID and return a malformed reponse.
    respx_mock.get(jwks_url).respond(json=["foo"])
    token = create_upstream_oidc_jwt("some-user", kid="malformed")
    with pytest.raises(FetchKeysError):
        await verifier.verify_token(token)

    # Return a 404 error.
    respx_mock.get(jwks_url).respond(404)
    with pytest.raises(ProviderWebError):
        await verifier.verify_token(token)

    # Fix the JWKS handler but register a malformed URL as the OpenID Connect
    # configuration endpoint, which should be checked first.
    jwks.keys[1].kid = "another-kid"
    respx_mock.get(jwks_url).respond(json=jwks.model_dump())
    respx_mock.get(oidc_url).respond(json=["foo"])
    token = create_upstream_oidc_jwt("some-user", kid="another-kid")
    with pytest.raises(FetchKeysError):
        await verifier.verify_token(token)

    # Try again with a working OpenID Connect configuration.
    respx_mock.get(oidc_url).respond(json={"jwks_uri": jwks_url})
    assert await verifier.verify_token(token)


@pytest.mark.asyncio
async def test_issuer_with_path(
    tmp_path: Path, respx_mock: respx.Router, factory: Factory
) -> None:
    config = await reconfigure(tmp_path, "oidc-subdomain", factory)
    assert config.oidc
    verifier = factory.create_oidc_token_verifier()

    # Initial working JWKS configuration.
    jwks = TEST_KEYPAIR.public_key_as_jwks("some-kid")

    # Register that handler at the well-known JWKS endpoint.  This will return
    # a connection refused from the OpenID Connect endpoint.
    jwks_url = config.oidc.issuer + "/.well-known/jwks.json"
    oidc_url = config.oidc.issuer + "/.well-known/openid-configuration"
    respx_mock.get(jwks_url).respond(json=jwks.model_dump())
    respx_mock.get(oidc_url).respond(json={"jwks_uri": jwks_url})

    # Check token verification with this configuration.
    token = create_upstream_oidc_jwt("some-user", kid="some-kid")
    assert await verifier.verify_token(token)
