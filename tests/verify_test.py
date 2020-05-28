"""Tests for the gafaelfawr.verify package."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt
import pytest
from jwt.exceptions import InvalidIssuerError

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.tokens import Token
from gafaelfawr.verify import MissingClaimsException, UnknownKeyIdException

if TYPE_CHECKING:
    from tests.setup import SetupTestCallable
    from typing import Any, Dict, Optional


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
    token = setup.create_oidc_token()
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
