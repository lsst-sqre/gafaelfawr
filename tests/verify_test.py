"""Tests for the gafaelfawr.verify package."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urljoin

import jwt
import pytest
import respx
from _pytest._code import ExceptionInfo
from jwt.exceptions import InvalidIssuerError

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.exceptions import (
    FetchKeysException,
    MissingClaimsException,
    UnknownAlgorithmException,
    UnknownKeyIdException,
)
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.models.oidc import OIDCToken

from .support.oidc import mock_oidc_provider_config
from .support.settings import configure
from .support.tokens import create_upstream_oidc_token


def encode_token(
    payload: Dict[str, Any], keypair: RSAKeyPair, kid: Optional[str] = None
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
async def test_verify_oidc(
    tmp_path: Path, respx_mock: respx.Router, factory: ComponentFactory
) -> None:
    config = await configure(tmp_path, "oidc")
    factory.reconfigure(config)
    verifier = factory.create_token_verifier()

    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=24)
    payload: Dict[str, Any] = {
        "aud": config.verifier.oidc_aud,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    keypair = config.issuer.keypair
    token = encode_token(payload, keypair)
    excinfo: ExceptionInfo[Exception]

    # Missing iss.
    with pytest.raises(InvalidIssuerError) as excinfo:
        await verifier.verify_oidc_token(token)
    assert str(excinfo.value) == "No iss claim in token"

    # Missing kid.
    payload["iss"] = "https://bogus.example.com/"
    token = encode_token(payload, keypair)
    with pytest.raises(UnknownKeyIdException) as excinfo:
        await verifier.verify_oidc_token(token)
    assert str(excinfo.value) == "No kid in token header"

    # Unknown issuer.
    token = encode_token(payload, keypair, kid="a-kid")
    with pytest.raises(InvalidIssuerError) as excinfo:
        await verifier.verify_oidc_token(token)
    assert str(excinfo.value) == "Unknown issuer: https://bogus.example.com/"

    # Unknown kid.
    payload["iss"] = config.verifier.oidc_iss
    token = encode_token(payload, keypair, kid="a-kid")
    with pytest.raises(UnknownKeyIdException) as excinfo:
        await verifier.verify_oidc_token(token)
    expected = f"kid a-kid not allowed for {config.verifier.oidc_iss}"
    assert str(excinfo.value) == expected

    # Missing username claim.
    await mock_oidc_provider_config(respx_mock, keypair)
    kid = config.verifier.oidc_kids[0]
    token = encode_token(payload, config.issuer.keypair, kid=kid)
    with pytest.raises(MissingClaimsException) as excinfo:
        await verifier.verify_oidc_token(token)
    expected = f"No {config.verifier.username_claim} claim in token"
    assert str(excinfo.value) == expected

    # Missing UID claim.  This is only diagnosed when get_uid_from_token is
    # called, not during the initial verification, since we do not verify the
    # UID claim if UIDs are retrieved from LDAP instead.
    await mock_oidc_provider_config(respx_mock, keypair)
    payload[config.verifier.username_claim] = "some-user"
    token = encode_token(payload, config.issuer.keypair, kid=kid)
    verified_token = await verifier.verify_oidc_token(token)
    with pytest.raises(MissingClaimsException) as excinfo:
        verifier.get_uid_from_token(verified_token)
    expected = f"No {config.verifier.uid_claim} claim in token"
    assert str(excinfo.value) == expected


@pytest.mark.asyncio
async def test_verify_oidc_no_kids(
    tmp_path: Path, respx_mock: respx.Router, factory: ComponentFactory
) -> None:
    config = await configure(tmp_path, "oidc-no-kids")
    factory.reconfigure(config)
    keypair = config.issuer.keypair
    verifier = factory.create_token_verifier()
    await mock_oidc_provider_config(respx_mock, keypair, "kid")

    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=24)
    payload: Dict[str, Any] = {
        "aud": config.verifier.oidc_aud,
        "iat": int(now.timestamp()),
        "iss": config.verifier.oidc_iss,
        "exp": int(exp.timestamp()),
    }
    token = encode_token(payload, keypair, kid="a-kid")
    with pytest.raises(UnknownKeyIdException) as excinfo:
        await verifier.verify_oidc_token(token)
    expected = f"Issuer {config.verifier.oidc_iss} has no kid a-kid"
    assert str(excinfo.value) == expected


@pytest.mark.asyncio
async def test_key_retrieval(
    tmp_path: Path, respx_mock: respx.Router, factory: ComponentFactory
) -> None:
    config = await configure(tmp_path, "oidc-no-kids")
    factory.reconfigure(config)
    assert config.oidc
    verifier = factory.create_token_verifier()

    # Initial working JWKS configuration.
    jwks = config.issuer.keypair.public_key_as_jwks("some-kid")

    # Register that handler at the well-known JWKS endpoint.  This will return
    # a connection refused from the OpenID Connect endpoint.
    jwks_url = urljoin(config.oidc.issuer, "/.well-known/jwks.json")
    oidc_url = urljoin(config.oidc.issuer, "/.well-known/openid-configuration")
    respx_mock.get(jwks_url).respond(json=jwks.dict())
    respx_mock.get(oidc_url).respond(404)

    # Check token verification with this configuration.
    token = await create_upstream_oidc_token(kid="some-kid")
    assert await verifier.verify_oidc_token(token)

    # Wrong algorithm for the key.
    jwks.keys[0].alg = "ES256"
    respx_mock.get(jwks_url).respond(json=jwks.dict())
    with pytest.raises(UnknownAlgorithmException):
        await verifier.verify_oidc_token(token)

    # Should go back to working if we fix the algorithm and add more keys.
    # Add an explicit 404 from the OpenID connect endpoint.
    respx_mock.get(oidc_url).respond(404)
    jwks.keys[0].alg = ALGORITHM
    keypair = RSAKeyPair.generate()
    jwks.keys.insert(0, keypair.public_key_as_jwks("a-kid").keys[0])
    respx_mock.get(jwks_url).respond(json=jwks.dict())
    assert await verifier.verify_oidc_token(token)

    # Try with a new key ID and return a malformed reponse.
    respx_mock.get(jwks_url).respond(json=["foo"])
    token = await create_upstream_oidc_token(kid="malformed")
    with pytest.raises(FetchKeysException):
        await verifier.verify_oidc_token(token)

    # Return a 404 error.
    respx_mock.get(jwks_url).respond(404)
    with pytest.raises(FetchKeysException):
        await verifier.verify_oidc_token(token)

    # Fix the JWKS handler but register a malformed URL as the OpenID Connect
    # configuration endpoint, which should be checked first.
    jwks.keys[1].kid = "another-kid"
    respx_mock.get(jwks_url).respond(json=jwks.dict())
    respx_mock.get(oidc_url).respond(json=["foo"])
    token = await create_upstream_oidc_token(kid="another-kid")
    with pytest.raises(FetchKeysException):
        await verifier.verify_oidc_token(token)

    # Try again with a working OpenID Connect configuration.
    respx_mock.get(oidc_url).respond(json={"jwks_uri": jwks_url})
    assert await verifier.verify_oidc_token(token)
