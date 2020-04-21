"""Tests for the /auth route."""

from __future__ import annotations

import base64
import time
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from jwt_authorizer.constants import ALGORITHM
from tests.setup import SetupTest

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


def assert_www_authenticate_header_matches(header: str, error: str) -> None:
    header_method, header_info = header.split(" ", 1)
    assert header_method == "Bearer"
    data = header_info.split(",")
    assert data[0] == 'realm="testing"'
    assert data[1] == f'error="{error}"'
    assert data[2].startswith("error_description=")


async def test_no_auth(tmp_path: Path, aiohttp_client: TestClient) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    r = await client.get("/auth", params={"capability": "exec:admin"})
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]
    assert_www_authenticate_header_matches(
        r.headers["WWW-Authenticate"], "Unable to find token"
    )

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": "Bearer"},
    )
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]
    assert_www_authenticate_header_matches(
        r.headers["WWW-Authenticate"], "Unable to find token"
    )

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": "Bearer token"},
    )
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]
    assert_www_authenticate_header_matches(
        r.headers["WWW-Authenticate"], "Invalid token"
    )


async def test_access_denied(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token()

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 403
    body = await r.text()
    assert "Missing required scopes" in body
    assert "X-Auth-Request-Token-Scopes" not in r.headers
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"


async def test_satisfy_all(tmp_path: Path, aiohttp_client: TestClient) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token(scope="exec:test")

    r = await client.get(
        "/auth",
        params=[("capability", "exec:test"), ("capability", "exec:admin")],
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 403
    body = await r.text()
    assert "Missing required scopes" in body
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:test"
    assert (
        r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin exec:test"
    )
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"


async def test_success(tmp_path: Path, aiohttp_client: TestClient) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:admin read:all"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"
    assert r.headers["X-Auth-Request-User"] == "some-user"
    assert r.headers["X-Auth-Request-Uid"] == "1000"
    assert r.headers["X-Auth-Request-Groups"] == "admin"
    assert r.headers["X-Auth-Request-Token"] == token.encoded


async def test_success_any(tmp_path: Path, aiohttp_client: TestClient) -> None:
    """Test satisfy=any as an /auth parameter.

    Ask for either ``exec:admin`` or ``exec:test`` and pass in credentials
    with only ``exec:test``.  Ensure they are accepted but also the headers
    don't claim the client has ``exec:admin``.
    """
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token(groups=["test"], scope="exec:test")

    r = await client.get(
        "/auth",
        params=[
            ("capability", "exec:admin"),
            ("capability", "exec:test"),
            ("satisfy", "any"),
        ],
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:test"
    assert (
        r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin exec:test"
    )
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "any"
    assert r.headers["X-Auth-Request-Groups"] == "test"


async def test_forwarded(tmp_path: Path, aiohttp_client: TestClient) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token(groups=["test"], scope="exec:admin")

    # Check that the bogus basic auth parameter is ignored.
    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={
            "Authorization": "Basic blah",
            "X-Forwarded-Access-Token": token.encoded,
        },
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"

    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={
            "Authorization": "Basic blah",
            "X-Forwarded-Ticket-Id-Token": token.encoded,
        },
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"


async def test_basic(tmp_path: Path, aiohttp_client: TestClient) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token(groups=["test"], scope="exec:admin")

    basic = f"{token.encoded}:x-oauth-basic".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"

    basic = f"x-oauth-basic:{token.encoded}".encode()
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
    basic = f"{token.encoded}:something-else".encode()
    basic_b64 = base64.b64encode(basic).decode()
    r = await client.get(
        "/auth",
        params={"capability": "exec:admin"},
        headers={"Authorization": f"Basic {basic_b64}"},
    )
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"


async def test_reissue_internal(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    """Test requesting token reissuance to an internal audience."""
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token(groups=["admin"], scope="exec:admin")

    r = await client.get(
        "/auth",
        params={
            "capability": "exec:admin",
            "audience": "https://example.com/api",
        },
        headers={"Authorization": f"Bearer {token.encoded}"},
    )
    assert r.status == 200
    new_encoded_token = r.headers["X-Auth-Request-Token"]
    assert token != new_encoded_token

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
        "scope": "exec:admin read:all",
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
