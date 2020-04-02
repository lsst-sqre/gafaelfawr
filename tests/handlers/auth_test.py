"""Tests for the /auth route."""

from __future__ import annotations

import base64
import os
import time
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.session import SessionStore, Ticket
from tests.util import RSAKeyPair, create_test_app, create_test_token

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient


def assert_www_authenticate_header_matches(
    header: str, method: str, error: str
) -> None:
    header_method, header_info = header.split(" ", 1)
    assert header_method == method
    if header_method == "Basic":
        assert header_info == 'realm="tokens"'
    else:
        data = header_info.split(",")
        assert data[0] == 'realm="tokens"'
        assert data[1] == f'error="{error}"'
        assert data[2].startswith("error_description=")


async def test_no_auth(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    client = await aiohttp_client(app)

    r = await client.get("/auth", params={"capability": "exec:admin"})
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]
    assert_www_authenticate_header_matches(
        r.headers["WWW-Authenticate"], "Bearer", "No Authorization header"
    )

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": "Bearer"},
    )
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]
    assert_www_authenticate_header_matches(
        r.headers["WWW-Authenticate"], "Bearer", "Unable to find token"
    )

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": "Bearer token"},
    )
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]
    assert_www_authenticate_header_matches(
        r.headers["WWW-Authenticate"], "Bearer", "Invalid token"
    )


async def test_access_denied(aiohttp_client: TestClient) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair)
    app = await create_test_app(keypair)
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status == 403
    body = await r.text()
    assert "No Capability group found in user's `isMemberOf`" in body
    assert r.headers["X-Auth-Request-Token-Capabilities"] == ""
    assert r.headers["X-Auth-Request-Capabilities-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "all"


async def test_satisfy_all(aiohttp_client: TestClient) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["test"])
    app = await create_test_app(keypair)
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth",
        params=[("capability", "exec:test"), ("capability", "exec:admin")],
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status == 403
    body = await r.text()
    assert "No Capability group found in user's `isMemberOf`" in body
    assert r.headers["X-Auth-Request-Token-Capabilities"] == "exec:test"
    assert (
        r.headers["X-Auth-Request-Capabilities-Accepted"]
        == "exec:admin exec:test"
    )
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "all"


async def test_success(aiohttp_client: TestClient) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["admin"])
    app = await create_test_app(keypair)
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status == 200
    assert (
        r.headers["X-Auth-Request-Token-Capabilities"] == "exec:admin read:all"
    )
    assert r.headers["X-Auth-Request-Capabilities-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"
    assert r.headers["X-Auth-Request-User"] == "some-user"
    assert r.headers["X-Auth-Request-Uid"] == "1000"
    assert r.headers["X-Auth-Request-Groups"] == "admin"
    assert r.headers["X-Auth-Request-Token"] == token
    assert r.headers["X-Auth-Request-Token-Ticket"] == ""


async def test_success_any(aiohttp_client: TestClient) -> None:
    """Test satisfy=any as an /auth parameter.

    Ask for either ``exec:admin`` or ``exec:test`` and pass in credentials
    with only ``exec:test``.  Ensure they are accepted but also the headers
    don't claim the client has ``exec:admin``.
    """
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["test"])
    app = await create_test_app(keypair)
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth",
        params=[
            ("capability", "exec:admin"),
            ("capability", "exec:test"),
            ("satisfy", "any"),
        ],
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Capabilities"] == "exec:test"
    assert (
        r.headers["X-Auth-Request-Capabilities-Accepted"]
        == "exec:admin exec:test"
    )
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "any"
    assert r.headers["X-Auth-Request-Groups"] == "test"


async def test_forwarded(aiohttp_client: TestClient) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["admin"])
    app = await create_test_app(keypair)
    client = await aiohttp_client(app)

    # Check that the bogus basic auth parameter is ignored.
    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={
            "Authorization": "Basic blah",
            "X-Forwarded-Access-Token": token,
        },
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={
            "Authorization": "Basic blah",
            "X-Forwarded-Ticket-Id-Token": token,
        },
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"


async def test_basic(aiohttp_client: TestClient) -> None:
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["admin"])
    app = await create_test_app(keypair)
    client = await aiohttp_client(app)

    basic = f"{token}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"

    basic = f"x-oauth-basic:{token}".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"

    # We currently fall back on using the username if x-oauth-basic doesn't
    # appear anywhere in the auth string.
    basic = f"{token}:something-else".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"


async def test_reissue(aiohttp_client: TestClient) -> None:
    """Test that an upstream token is reissued properly."""
    keypair = RSAKeyPair()
    ticket = Ticket()
    ticket_handle = ticket.encode("oauth2_proxy")
    ticket_b64 = base64.urlsafe_b64encode(ticket_handle.encode()).decode()
    cookie = f"{ticket_b64}|32132781|blahblah"
    token = create_test_token(
        keypair,
        ["admin"],
        kid="orig-kid",
        aud="https://test.example.com/",
        iss="https://orig.example.com/",
        jti=ticket.as_handle("oauth2_proxy"),
    )
    session_secret = os.urandom(16)
    app = await create_test_app(keypair, session_secret)
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Bearer {token}"},
        cookies={"oauth2_proxy": cookie},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Ticket"] == ticket_handle
    new_token = r.headers["X-Auth-Request-Token"]
    assert token != new_token

    assert jwt.get_unverified_header(new_token) == {
        "alg": ALGORITHM,
        "typ": "JWT",
        "kid": "some-kid",
    }

    decoded_token = jwt.decode(
        new_token,
        keypair.public_key_as_pem(),
        algorithms=ALGORITHM,
        audience="https://example.com/",
    )
    assert decoded_token == {
        "act": {
            "aud": "https://test.example.com/",
            "iss": "https://orig.example.com/",
            "jti": ticket.as_handle("oauth2_proxy"),
        },
        "aud": "https://example.com/",
        "email": "some-user@example.com",
        "exp": ANY,
        "iat": ANY,
        "isMemberOf": [{"name": "admin"}],
        "iss": "https://test.example.com/",
        "jti": ticket.as_handle("oauth2_proxy"),
        "scope": "exec:admin read:all",
        "sub": "some-user",
        "uid": "some-user",
        "uidNumber": "1000",
    }
    now = time.time()
    exp_minutes = app["jwt_authorizer/config"].issuer.exp_minutes
    expected_exp = now + exp_minutes * 60
    assert expected_exp - 5 <= decoded_token["exp"] <= expected_exp + 5
    assert now - 5 <= decoded_token["iat"] <= now + 5

    redis_client = app["jwt_authorizer/redis"]
    session_store = SessionStore("oauth2_proxy", session_secret, redis_client)
    session = await session_store.get_session(ticket)
    assert session
    assert session.token == new_token
    assert session.user == "some-user@example.com"


async def test_reissue_internal(aiohttp_client: TestClient) -> None:
    """Test requesting token reissuance to an internal audience."""
    keypair = RSAKeyPair()
    token = create_test_token(keypair, ["admin"])
    session_secret = os.urandom(16)
    app = await create_test_app(keypair, session_secret)
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth",
        params={
            "capability": "exec:admin",
            "audience": "https://example.com/api",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status == 200
    new_token = r.headers["X-Auth-Request-Token"]
    assert token != new_token
    ticket = Ticket.from_str(
        "oauth2_proxy", r.headers["X-Auth-Request-Token-Ticket"]
    )

    assert jwt.get_unverified_header(new_token) == {
        "alg": ALGORITHM,
        "typ": "JWT",
        "kid": "some-kid",
    }

    decoded_token = jwt.decode(
        new_token,
        keypair.public_key_as_pem(),
        algorithms=ALGORITHM,
        audience="https://example.com/api",
    )
    assert decoded_token == {
        "act": {
            "aud": "https://example.com/",
            "iss": "https://test.example.com/",
            "jti": "some-unique-id",
        },
        "aud": "https://example.com/api",
        "email": "some-user@example.com",
        "exp": ANY,
        "iat": ANY,
        "isMemberOf": [{"name": "admin"}],
        "iss": "https://test.example.com/",
        "jti": ticket.as_handle("oauth2_proxy"),
        "sub": "some-user",
        "uid": "some-user",
        "uidNumber": "1000",
    }
    now = time.time()
    exp_minutes = app["jwt_authorizer/config"].issuer.exp_minutes
    expected_exp = now + exp_minutes * 60
    assert expected_exp - 5 <= decoded_token["exp"] <= expected_exp + 5
    assert now - 5 <= decoded_token["iat"] <= now + 5

    redis_client = app["jwt_authorizer/redis"]
    session_store = SessionStore("oauth2_proxy", session_secret, redis_client)
    session = await session_store.get_session(ticket)
    assert session
    assert session.token == new_token
    assert session.email == "some-user@example.com"
    assert session.user == "some-user@example.com"
    assert now - 5 <= session.created_at.timestamp() <= now + 5
    assert session.expires_on.timestamp() == decoded_token["exp"]
