"""Tests for the /login route."""

from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

from jwt_authorizer.config import ALGORITHM
from jwt_authorizer.providers import GitHubProvider
from tests.util import create_test_app

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient


async def test_login(aiohttp_client: TestClient) -> None:
    config = {
        "GITHUB.CLIENT_ID": "some-client-id",
        "GITHUB.CLIENT_SECRET": "some-client-secret",
    }
    app = await create_test_app(None, None, **config)
    client = await aiohttp_client(app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        params={"rd": "https://example.com/foo?a=bar&b=baz"},
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    assert url.scheme == "https"
    assert "github.com" in url.netloc
    assert url.query
    query = parse_qs(url.query)
    assert query == {
        "client_id": ["some-client-id"],
        "scope": [" ".join(GitHubProvider._SCOPES)],
        "state": [ANY],
    }

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo?a=bar&b=baz"

    # Check that the /auth route works and finds our token.
    r = await client.get("/auth", params={"capability": "read:all"})
    assert r.status == 200
    assert r.headers["X-Auth-Request-Token-Capabilities"] == "read:all"
    assert r.headers["X-Auth-Request-Capabilities-Accepted"] == "read:all"
    assert r.headers["X-Auth-Request-Capabilities-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == "githubuser@example.com"
    assert r.headers["X-Auth-Request-User"] == "githubuser"
    assert r.headers["X-Auth-Request-Uid"] == "123456"
    expected = "org-a-team,org-other-team,other-org-team-with-very--F279yg"
    assert r.headers["X-Auth-Request-Groups"] == expected
    assert r.headers["X-Auth-Request-Token"]

    # Now ask for the ticket in the encrypted session to be analyzed, and
    # verify the internals of the ticket from GitHub authentication.
    r = await client.get("/auth/analyze")
    assert r.status == 200
    data = await r.json()
    assert data == {
        "ticket": {"ticket_id": ANY, "secret": ANY},
        "session": {
            "email": "githubuser@example.com",
            "user": "githubuser@example.com",
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {"alg": ALGORITHM, "typ": "JWT", "kid": "some-kid"},
            "data": {
                "aud": "https://example.com/",
                "email": "githubuser@example.com",
                "exp": ANY,
                "iat": ANY,
                "isMemberOf": [
                    {"name": "org-a-team", "id": 1000},
                    {"name": "org-other-team", "id": 1001},
                    {"name": "other-org-team-with-very--F279yg", "id": 1002},
                ],
                "iss": "https://test.example.com/",
                "jti": ANY,
                "uid": "githubuser",
                "uidNumber": "123456",
            },
            "valid": True,
        },
    }


async def test_login_redirect_header(aiohttp_client: TestClient) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    config = {
        "GITHUB.CLIENT_ID": "some-client-id",
        "GITHUB.CLIENT_SECRET": "some-client-secret",
    }
    app = await create_test_app(None, None, **config)
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

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo?a=bar&b=baz"


async def test_login_no_destination(aiohttp_client: TestClient) -> None:
    config = {
        "GITHUB.CLIENT_ID": "some-client-id",
        "GITHUB.CLIENT_SECRET": "some-client-secret",
    }
    app = await create_test_app(None, None, **config)
    client = await aiohttp_client(app)

    # Simulate the initial authentication request.
    r = await client.get("/login", allow_redirects=False)
    assert r.status == 400


async def test_cookie_auth_with_token(aiohttp_client: TestClient) -> None:
    """Test that cookie auth takes precedence over an Authorization header.

    JupyterHub sends an Authorization header in its internal requests with
    type token.  We want to ensure that we prefer our session cookie, rather
    than try to unsuccessfully parse that header.  Test this by completing a
    login to get a valid session and then make a request with a bogus
    Authorization header.
    """
    config = {
        "GITHUB.CLIENT_ID": "some-client-id",
        "GITHUB.CLIENT_SECRET": "some-client-secret",
    }
    app = await create_test_app(None, None, **config)
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

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303
    assert r.headers["Location"] == "https://example.com/foo?a=bar&b=baz"

    # Now make a request to the /auth endpoint with a bogus token.
    r = await client.get("/auth", params={"capability": "read:all"})
    assert r.status == 200
    assert r.headers["X-Auth-Request-Email"] == "githubuser@example.com"
