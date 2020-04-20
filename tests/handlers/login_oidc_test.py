"""Tests for the /login route with OpenID Connect."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

from jwt_authorizer.constants import ALGORITHM
from tests.support.app import create_test_app, store_secret

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_login(tmp_path: Path, aiohttp_client: TestClient) -> None:
    secret_path = store_secret(tmp_path, "oidc", b"some-client-secret")
    config = {
        "OIDC.CLIENT_ID": "some-client-id",
        "OIDC.CLIENT_SECRET_FILE": str(secret_path),
        "OIDC.LOGIN_URL": "https://example.com/oidc/login",
        "OIDC.LOGIN_PARAMS": {"skin": "test"},
        "OIDC.REDIRECT_URL": "https://example.com/login",
        "OIDC.TOKEN_URL": "https://example.com/token",
        "OIDC.SCOPES": ["email", "voPerson"],
    }
    app = await create_test_app(tmp_path, **config)
    client = await aiohttp_client(app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        params={"rd": "https://example.com/foo?a=bar&b=baz"},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"].startswith("https://example.com/oidc/login")
    url = urlparse(r.headers["Location"])
    assert url.query
    query = parse_qs(url.query)
    assert query == {
        "client_id": ["some-client-id"],
        "redirect_uri": ["https://example.com/login"],
        "response_type": ["code"],
        "scope": ["openid email voPerson"],
        "skin": ["test"],
        "state": [ANY],
    }

    # Simulate the return from the provider.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo?a=bar&b=baz"

    # Check that the /auth route works and finds our token.
    r = await client.get("/auth", params={"capability": "exec:admin"})
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "exec:admin read:all"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "exec:admin"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == "some-user@example.com"
    assert r.headers["X-Auth-Request-User"] == "some-user"
    assert r.headers["X-Auth-Request-Uid"] == "1000"
    assert r.headers["X-Auth-Request-Groups"] == "admin"
    assert r.headers["X-Auth-Request-Token"]

    # Now ask for the ticket in the encrypted session to be analyzed, and
    # verify the internals of the ticket from GitHub authentication.
    r = await client.get("/auth/analyze")
    assert r.status == 200
    data = await r.json()
    assert data == {
        "handle": {"key": ANY, "secret": ANY},
        "session": {
            "email": "some-user@example.com",
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {"alg": ALGORITHM, "typ": "JWT", "kid": "some-kid"},
            "data": {
                "act": {
                    "aud": "https://test.example.com/",
                    "iss": "https://upstream.example.com/",
                    "jti": ANY,
                },
                "aud": "https://example.com/",
                "email": "some-user@example.com",
                "exp": ANY,
                "iat": ANY,
                "isMemberOf": [{"name": "admin"}],
                "iss": "https://test.example.com/",
                "jti": ANY,
                "sub": "some-user",
                "uid": "some-user",
                "uidNumber": "1000",
            },
            "valid": True,
        },
    }


async def test_login_redirect_header(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    secret_path = store_secret(tmp_path, "oidc", b"some-client-secret")
    config = {
        "OIDC.CLIENT_ID": "some-client-id",
        "OIDC.CLIENT_SECRET_FILE": str(secret_path),
        "OIDC.LOGIN_URL": "https://example.com/oidc/login",
        "OIDC.LOGIN_PARAMS": {"skin": "test"},
        "OIDC.REDIRECT_URL": "https://example.com/login",
        "OIDC.TOKEN_URL": "https://example.com/token",
        "OIDC.SCOPES": ["email", "voPerson"],
    }
    app = await create_test_app(tmp_path, **config)
    client = await aiohttp_client(app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        headers={
            "X-Auth-Request-Redirect": "https://example.com/foo?a=bar&b=baz"
        },
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo?a=bar&b=baz"


async def test_oauth2_callback(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    """Test the compatibility /oauth2/callback route."""
    secret_path = store_secret(tmp_path, "oidc", b"some-client-secret")
    config = {
        "OIDC.CLIENT_ID": "some-client-id",
        "OIDC.CLIENT_SECRET_FILE": str(secret_path),
        "OIDC.LOGIN_URL": "https://example.com/oidc/login",
        "OIDC.LOGIN_PARAMS": {"skin": "test"},
        "OIDC.REDIRECT_URL": "https://example.com/oauth2/sign_in",
        "OIDC.TOKEN_URL": "https://example.com/token",
        "OIDC.SCOPES": ["email", "voPerson"],
    }
    app = await create_test_app(tmp_path, **config)
    client = await aiohttp_client(app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        params={"rd": "https://example.com/foo"},
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)
    assert query["redirect_uri"][0] == "https://example.com/oauth2/sign_in"

    # Simulate the return from the OpenID Connect provider.
    r = await client.get(
        "/oauth2/callback",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo"
