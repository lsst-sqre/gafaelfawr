"""Tests for the gafaelfawr.verify package."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import jwt
import pytest
from jwt.exceptions import InvalidIssuerError

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.exceptions import (
    FetchKeysException,
    MissingClaimsException,
    UnknownAlgorithmException,
    UnknownKeyIdException,
)
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.models.oidc import OIDCToken

if TYPE_CHECKING:
    from typing import Any, Dict, Optional

    from _pytest._code import ExceptionInfo

    from tests.support.setup import SetupTest


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
async def test_verify_oidc(setup: SetupTest) -> None:
    await setup.configure("oidc")
    verifier = setup.factory.create_token_verifier()

    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=24)
    payload: Dict[str, Any] = {
        "aud": setup.config.verifier.oidc_aud,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    keypair = setup.config.issuer.keypair
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
    payload["iss"] = setup.config.verifier.oidc_iss
    token = encode_token(payload, keypair, kid="a-kid")
    with pytest.raises(UnknownKeyIdException) as excinfo:
        await verifier.verify_oidc_token(token)
    expected = f"kid a-kid not allowed for {setup.config.verifier.oidc_iss}"
    assert str(excinfo.value) == expected

    # Missing username claim.
    setup.set_oidc_configuration_response(keypair)
    kid = setup.config.verifier.oidc_kids[0]
    token = encode_token(payload, setup.config.issuer.keypair, kid=kid)
    with pytest.raises(MissingClaimsException) as excinfo:
        await verifier.verify_oidc_token(token)
    expected = f"No {setup.config.verifier.username_claim} claim in token"
    assert str(excinfo.value) == expected

    # Missing UID claim.
    setup.set_oidc_configuration_response(keypair)
    payload[setup.config.verifier.username_claim] = "some-user"
    token = encode_token(payload, setup.config.issuer.keypair, kid=kid)
    with pytest.raises(MissingClaimsException) as excinfo:
        await verifier.verify_oidc_token(token)
    expected = f"No {setup.config.verifier.uid_claim} claim in token"
    assert str(excinfo.value) == expected


@pytest.mark.asyncio
async def test_verify_oidc_no_kids(setup: SetupTest) -> None:
    await setup.configure("oidc-no-kids")
    verifier = setup.factory.create_token_verifier()
    setup.set_oidc_configuration_response(setup.config.issuer.keypair, "kid")

    now = datetime.now(timezone.utc)
    exp = now + timedelta(days=24)
    payload: Dict[str, Any] = {
        "aud": setup.config.verifier.oidc_aud,
        "iat": int(now.timestamp()),
        "iss": setup.config.verifier.oidc_iss,
        "exp": int(exp.timestamp()),
    }
    keypair = setup.config.issuer.keypair
    token = encode_token(payload, keypair, kid="a-kid")
    with pytest.raises(UnknownKeyIdException) as excinfo:
        await verifier.verify_oidc_token(token)
    expected = f"Issuer {setup.config.verifier.oidc_iss} has no kid a-kid"
    assert str(excinfo.value) == expected


@pytest.mark.asyncio
async def test_key_retrieval(setup: SetupTest) -> None:
    await setup.configure("oidc-no-kids")
    assert setup.config.oidc
    verifier = setup.factory.create_token_verifier()

    # Initial working JWKS configuration.
    jwks = setup.config.issuer.keypair.public_key_as_jwks("some-kid")

    # Register that handler at the well-known JWKS endpoint.  This will return
    # a connection refused from the OpenID Connect endpoint.
    jwks_url = urljoin(setup.config.oidc.issuer, "/.well-known/jwks.json")
    oidc_url = urljoin(
        setup.config.oidc.issuer, "/.well-known/openid-configuration"
    )
    setup.respx_mock.get(jwks_url).respond(json=jwks.dict())
    setup.respx_mock.get(oidc_url).respond(404)

    # Check token verification with this configuration.
    token = setup.create_upstream_oidc_token(kid="some-kid")
    assert await verifier.verify_oidc_token(token)

    # Wrong algorithm for the key.
    jwks.keys[0].alg = "ES256"
    setup.respx_mock.get(jwks_url).respond(json=jwks.dict())
    with pytest.raises(UnknownAlgorithmException):
        await verifier.verify_oidc_token(token)

    # Should go back to working if we fix the algorithm and add more keys.
    # Add an explicit 404 from the OpenID connect endpoint.
    setup.respx_mock.get(oidc_url).respond(404)
    jwks.keys[0].alg = ALGORITHM
    keypair = RSAKeyPair.generate()
    jwks.keys.insert(0, keypair.public_key_as_jwks("a-kid").keys[0])
    setup.respx_mock.get(jwks_url).respond(json=jwks.dict())
    assert await verifier.verify_oidc_token(token)

    # Try with a new key ID and return a malformed reponse.
    setup.respx_mock.get(jwks_url).respond(json=["foo"])
    token = setup.create_upstream_oidc_token(kid="malformed")
    with pytest.raises(FetchKeysException):
        await verifier.verify_oidc_token(token)

    # Return a 404 error.
    setup.respx_mock.get(jwks_url).respond(404)
    with pytest.raises(FetchKeysException):
        await verifier.verify_oidc_token(token)

    # Fix the JWKS handler but register a malformed URL as the OpenID Connect
    # configuration endpoint, which should be checked first.
    jwks.keys[1].kid = "another-kid"
    setup.respx_mock.get(jwks_url).respond(json=jwks.dict())
    setup.respx_mock.get(oidc_url).respond(json=["foo"])
    token = setup.create_upstream_oidc_token(kid="another-kid")
    with pytest.raises(FetchKeysException):
        await verifier.verify_oidc_token(token)

    # Try again with a working OpenID Connect configuration.
    setup.respx_mock.get(oidc_url).respond(json={"jwks_uri": jwks_url})
    assert await verifier.verify_oidc_token(token)
