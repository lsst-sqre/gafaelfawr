"""Tests for the gafaelfawr.verify package."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY, Mock
from urllib.parse import urljoin

import jwt
import pytest
from aiohttp import ClientResponse
from jwt.exceptions import InvalidIssuerError

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.tokens import Token
from gafaelfawr.verify import (
    FetchKeysException,
    MissingClaimsException,
    UnknownAlgorithmException,
    UnknownKeyIdException,
)

if TYPE_CHECKING:
    from typing import Any, Dict, Optional

    from tests.setup import SetupTestCallable


def encode_token(
    payload: Dict[str, Any], keypair: RSAKeyPair, kid: Optional[str] = None
) -> Token:
    """Encode a token payload into a token manually."""
    headers = {}
    if kid:
        headers["kid"] = kid
    encoded = jwt.encode(
        payload,
        keypair.private_key_as_pem(),
        algorithm=ALGORITHM,
        headers=headers,
    ).decode()
    return Token(encoded=encoded)


async def test_analyze(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup(client=False)
    verifier = setup.factory.create_token_verifier()

    # Unknown issuer.
    token = setup.create_oidc_token(kid="kid")
    data = verifier.analyze_token(token)
    assert data == {
        "header": {"alg": ALGORITHM, "kid": ANY, "typ": "JWT"},
        "data": token.claims,
        "errors": [ANY],
        "valid": False,
    }


async def test_verify_oidc(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup(environment="oidc", client=False)
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
    payload[setup.config.verifier.username_claim] = "some-user"
    token = encode_token(payload, setup.config.issuer.keypair, kid=kid)
    with pytest.raises(MissingClaimsException) as excinfo:
        await verifier.verify_oidc_token(token)
    expected = f"No {setup.config.verifier.uid_claim} claim in token"
    assert str(excinfo.value) == expected


async def test_verify_oidc_no_kids(
    create_test_setup: SetupTestCallable,
) -> None:
    setup = await create_test_setup(environment="oidc-no-kids", client=False)
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


async def test_key_retrieval(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup(environment="oidc-no-kids", client=False)
    assert setup.config.oidc
    verifier = setup.factory.create_token_verifier()

    # Initial working JWKS configuration.
    keys = [setup.config.issuer.keypair.public_key_as_jwks("some-kid")]

    # Set up a handler that returns keys in JWKS format.
    def jwks_handler(
        headers: Dict[str, str], raise_for_status: bool
    ) -> ClientResponse:
        r = Mock(spec=ClientResponse)
        r.json.return_value = {"keys": keys}
        r.status = 200
        return r

    # Register that handler at the well-known JWKS endpoint.  We test using
    # the indrection via the well-known OpenID Configuration endpoint when
    # testing login via OpenID Connect.
    jwks_url = urljoin(setup.config.oidc.issuer, "/.well-known/jwks.json")
    setup.http_session.add_get_handler(jwks_url, jwks_handler)

    # Check token verification with this configuration.
    token = setup.create_oidc_token(kid="some-kid")
    assert await verifier.verify_oidc_token(token)

    # Changing to the wrong algorithm will still work because the key
    # retrieval should be cached.
    keys[0]["alg"] = "ES256"
    assert await verifier.verify_oidc_token(token)

    # Switch the key ID to avoid the cache, which should now fail.
    keys[0]["kid"] = "other-kid"
    token = setup.create_oidc_token(kid="other-kid")
    with pytest.raises(UnknownAlgorithmException):
        await verifier.verify_oidc_token(token)

    # Should go back to working if we fix the algorithm and add more keys.
    # The failure should not be cached.
    keys[0]["alg"] = ALGORITHM
    keypair = RSAKeyPair.generate()
    keys.insert(0, keypair.public_key_as_jwks("a-kid"))
    assert await verifier.verify_oidc_token(token)

    # Set up a malformed handler.
    def malformed_handler(
        headers: Dict[str, str], raise_for_status: bool
    ) -> ClientResponse:
        r = Mock(spec=ClientResponse)
        r.json.return_value = ["foo"]
        r.status = 200
        return r

    # Try with a new key ID to force another lookup.
    setup.http_session.add_get_handler(jwks_url, malformed_handler)
    token = setup.create_oidc_token(kid="malformed")
    with pytest.raises(FetchKeysException):
        await verifier.verify_oidc_token(token)

    # Fix the JWKS handler but register the same malformed handler as the
    # OpenID Connect configuration endpoint, which should be checked first.
    keys[0]["kid"] = "another-kid"
    token = setup.create_oidc_token(kid="another-kid")
    oidc_url = urljoin(
        setup.config.oidc.issuer, "/.well-known/openid-configuration"
    )
    setup.http_session.add_get_handler(jwks_url, jwks_handler)
    setup.http_session.add_get_handler(oidc_url, malformed_handler)
    with pytest.raises(FetchKeysException):
        await verifier.verify_oidc_token(token)
