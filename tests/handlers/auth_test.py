"""Tests for the /auth route."""

from __future__ import annotations

import base64
import time
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt
import pytest

from gafaelfawr.auth import AuthError, AuthErrorChallenge, AuthType
from gafaelfawr.constants import ALGORITHM
from tests.support.headers import parse_www_authenticate

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_no_auth(setup: SetupTest) -> None:
    r = await setup.client.get("/auth", params={"scope": "exec:admin"})
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "bearer"}
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "bogus"}
    )
    assert r.status_code == 422

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "basic"}
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Basic
    assert authenticate.realm == setup.config.realm


@pytest.mark.asyncio
async def test_invalid(setup: SetupTest) -> None:
    r = await setup.client.get("/auth")
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "value_error.missing"

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "satisfy": "foo"}
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "type_error.enum"

    r = await setup.client.get(
        "/auth", params={"scope": "exec:admin", "auth_type": "foo"}
    )
    assert r.status_code == 422
    assert r.json()["detail"][0]["type"] == "type_error.enum"


@pytest.mark.asyncio
async def test_invalid_auth(setup: SetupTest) -> None:
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "token foo"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": "Bearer token"},
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_token

    # Create an expired token.
    exp = (datetime.now(timezone.utc) - timedelta(days=24)).timestamp()
    token = setup.create_token(exp=int(exp), scope="exec:admin")
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status_code == 401
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_token


@pytest.mark.asyncio
async def test_access_denied(setup: SetupTest) -> None:
    token = setup.create_token()

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin"
    assert "Token missing required scope" in r.text


@pytest.mark.asyncio
async def test_auth_forbidden(setup: SetupTest) -> None:
    r = await setup.client.get(
        "/auth/forbidden",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin exec:test"
    assert "Token missing required scope" in r.text

    r = await setup.client.get(
        "/auth/forbidden", params={"scope": "exec:admin", "auth_type": "basic"}
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Basic
    assert authenticate.realm == setup.config.realm
    assert "Token missing required scope" in r.text


@pytest.mark.asyncio
async def test_satisfy_all(setup: SetupTest) -> None:
    token = setup.create_token(scope="exec:test")

    r = await setup.client.get(
        "/auth",
        params=[("scope", "exec:test"), ("scope", "exec:admin")],
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status_code == 403
    assert r.headers["Cache-Control"] == "no-cache, must-revalidate"
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.insufficient_scope
    assert authenticate.scope == "exec:admin exec:test"
    assert "Token missing required scope" in r.text


@pytest.mark.asyncio
async def test_success(setup: SetupTest) -> None:
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={
            "Authorization": f"Bearer {token.encoded}",
            "X-Forwarded-For": "192.0.2.1",
        },
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Client-Ip"] == "192.0.2.1"
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:admin read:all"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == token.email
    assert r.headers["X-Auth-Request-User"] == token.username
    assert r.headers["X-Auth-Request-Uid"] == token.uid
    assert r.headers["X-Auth-Request-Groups"] == "admin"
    assert r.headers["X-Auth-Request-Token"] == token.encoded


@pytest.mark.asyncio
async def test_success_any(setup: SetupTest) -> None:
    """Test ``satisfy=any`` as an ``/auth`` parameter.

    Ask for either ``exec:admin`` or ``exec:test`` and pass in credentials
    with only ``exec:test``.  Ensure they are accepted but also the headers
    don't claim the client has ``exec:admin``.
    """
    token = setup.create_token(groups=["test"], scope="exec:test")

    r = await setup.client.get(
        "/auth",
        params=[
            ("scope", "exec:admin"),
            ("scope", "exec:test"),
            ("satisfy", "any"),
        ],
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    scopes = "exec:admin exec:test"
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:test"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == scopes
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "any"
    assert r.headers["X-Auth-Request-Groups"] == "test"


@pytest.mark.asyncio
async def test_basic(setup: SetupTest) -> None:
    token = setup.create_token(groups=["test"], scope="exec:admin")

    basic = f"{token.encoded}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Email"] == token.email

    basic = f"x-oauth-basic:{token.encoded}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Email"] == token.email

    # We currently fall back on using the username if x-oauth-basic
    # doesn't appear anywhere in the auth string.
    basic = f"{token.encoded}:something-else".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Email"] == token.email


@pytest.mark.asyncio
async def test_basic_failure(setup: SetupTest) -> None:
    basic_b64 = base64.b64encode(b"bogus-string").decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 400
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
    assert authenticate.error == AuthError.invalid_request

    for basic in (b"foo:foo", b"x-oauth-basic:foo", b"foo:x-oauth-basic"):
        basic_b64 = base64.b64encode(basic).decode()
        r = await setup.client.get(
            "/auth",
            params={"scope": "exec:admin", "auth_type": "basic"},
            headers={"Authorization": f"Basic {basic_b64}"},
        )
        assert r.status_code == 401
        authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
        assert not isinstance(authenticate, AuthErrorChallenge)
        assert authenticate.auth_type == AuthType.Basic
        assert authenticate.realm == setup.config.realm


@pytest.mark.asyncio
async def test_handle(setup: SetupTest) -> None:
    """Test that a session handle can be used in Authorization."""
    handle = await setup.create_session(groups=["test"], scope="exec:admin")

    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Bearer {handle.encode()}"},
    )
    assert r.status_code == 200

    basic = f"{handle.encode()}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200

    basic = f"x-oauth-basic:{handle.encode()}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200

    # We currently fall back on using the username if x-oauth-basic
    # doesn't appear anywhere in the auth string.
    basic = f"{handle.encode()}:something-else".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_reissue_internal(setup: SetupTest) -> None:
    """Test requesting token reissuance to an internal audience."""
    token = setup.create_token(groups=["admin"], scope="exec:admin")

    r = await setup.client.get(
        "/auth",
        params={
            "scope": "exec:admin",
            "audience": setup.config.issuer.aud_internal,
        },
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status_code == 200
    new_encoded_token = r.headers["X-Auth-Request-Token"]
    assert token.encoded != new_encoded_token

    assert jwt.get_unverified_header(new_encoded_token) == {
        "alg": ALGORITHM,
        "typ": "JWT",
        "kid": setup.config.issuer.kid,
    }

    decoded_token = jwt.decode(
        new_encoded_token,
        setup.config.issuer.keypair.public_key_as_pem(),
        algorithms=ALGORITHM,
        audience=setup.config.issuer.aud_internal,
    )
    assert decoded_token == {
        "act": {
            "aud": setup.config.issuer.aud,
            "iss": setup.config.issuer.iss,
            "jti": token.jti,
        },
        "aud": setup.config.issuer.aud_internal,
        "email": token.email,
        "exp": ANY,
        "iat": ANY,
        "isMemberOf": [{"name": "admin"}],
        "iss": setup.config.issuer.iss,
        "jti": ANY,
        "scope": " ".join(sorted(setup.config.issuer.group_mapping["admin"])),
        "sub": token.claims["sub"],
        "uid": token.username,
        "uidNumber": token.uid,
    }
    now = time.time()
    expected_exp = now + setup.config.issuer.exp_minutes * 60
    assert expected_exp - 5 <= decoded_token["exp"] <= expected_exp + 5
    assert now - 5 <= decoded_token["iat"] <= now + 5

    # No session should be created for internal tokens.
    assert not await setup.redis.get(f"session:{decoded_token['jti']}")


@pytest.mark.asyncio
async def test_ajax_unauthorized(setup: SetupTest) -> None:
    """Test that AJAX requests without auth get 403, not 401."""
    r = await setup.client.get(
        "/auth",
        params={"scope": "exec:admin"},
        headers={"X-Requested-With": "XMLHttpRequest"},
    )
    assert r.status_code == 403
    authenticate = parse_www_authenticate(r.headers["WWW-Authenticate"])
    assert not isinstance(authenticate, AuthErrorChallenge)
    assert authenticate.auth_type == AuthType.Bearer
    assert authenticate.realm == setup.config.realm
