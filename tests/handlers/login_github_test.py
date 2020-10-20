"""Tests for the ``/login`` route with GitHub."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.providers.github import (
    GitHubProvider,
    GitHubTeam,
    GitHubUserInfo,
)

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from httpx import AsyncClient

    from tests.support.setup import SetupTest


async def test_login(
    setup: SetupTest, client: AsyncClient, caplog: LogCaptureFixture
) -> None:
    assert setup.config.github
    setup.set_github_token_response("some-code", "some-github-token")
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[
            GitHubTeam(slug="a-team", gid=1000, organization="org"),
            GitHubTeam(slug="other-team", gid=1001, organization="org"),
            GitHubTeam(
                slug="team-with-very-long-name",
                gid=1002,
                organization="other-org",
            ),
        ],
    )
    setup.set_github_userinfo_response("some-github-token", userinfo)
    return_url = "https://example.com:4444/foo?a=bar&b=baz"

    # Simulate the initial authentication request.
    r = await client.get(
        "/login", params={"rd": return_url}, allow_redirects=False
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert url.scheme == "https"
    assert "github.com" in url.netloc
    assert url.query
    query = parse_qs(url.query)
    assert query == {
        "client_id": [setup.config.github.client_id],
        "scope": [" ".join(GitHubProvider._SCOPES)],
        "state": [ANY],
    }
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == {
        "event": "Redirecting user to GitHub for authentication",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/login",
        "return_url": return_url,
        "remote": "127.0.0.1",
        "request_id": ANY,
        "user_agent": ANY,
    }

    # Simulate the return from GitHub.
    caplog.clear()
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == {
        "event": "Successfully authenticated user githubuser (123456)",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/login",
        "return_url": return_url,
        "remote": "127.0.0.1",
        "request_id": ANY,
        "scope": "read:all",
        "token": ANY,
        "user": "githubuser",
        "user_agent": ANY,
    }

    # Check that the /auth route works and finds our token.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Token-Scopes"] == "read:all"
    assert r.headers["X-Auth-Request-Scopes-Accepted"] == "read:all"
    assert r.headers["X-Auth-Request-Scopes-Satisfy"] == "all"
    assert r.headers["X-Auth-Request-Email"] == "githubuser@example.com"
    assert r.headers["X-Auth-Request-User"] == "githubuser"
    assert r.headers["X-Auth-Request-Uid"] == "123456"
    expected = "org-a-team,org-other-team,other-org-team-with-very--F279yg"
    assert r.headers["X-Auth-Request-Groups"] == expected
    assert r.headers["X-Auth-Request-Token"]

    # Now ask for the session handle in the encrypted session to be
    # analyzed, and verify the internals of the session handle from GitHub
    # authentication.
    r = await client.get("/auth/analyze")
    assert r.status_code == 200
    assert r.json() == {
        "handle": {"key": ANY, "secret": ANY},
        "session": {
            "email": "githubuser@example.com",
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {"alg": ALGORITHM, "typ": "JWT", "kid": "some-kid"},
            "data": {
                "aud": setup.config.issuer.aud,
                "email": "githubuser@example.com",
                "exp": ANY,
                "iat": ANY,
                "isMemberOf": [
                    {"name": "org-a-team", "id": 1000},
                    {"name": "org-other-team", "id": 1001},
                    {"name": "other-org-team-with-very--F279yg", "id": 1002},
                ],
                "iss": setup.config.issuer.iss,
                "jti": ANY,
                "name": "GitHub User",
                "scope": "read:all",
                "sub": "githubuser",
                "uid": "githubuser",
                "uidNumber": "123456",
            },
            "valid": True,
        },
    }


async def test_login_redirect_header(
    setup: SetupTest, client: AsyncClient
) -> None:
    """Test receiving the redirect header via X-Auth-Request-Redirect."""
    setup.set_github_token_response("some-code", "some-github-token")
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[],
    )
    setup.set_github_userinfo_response("some-github-token", userinfo)
    return_url = "https://example.com/foo?a=bar&b=baz"

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": return_url},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == return_url


async def test_login_no_destination(
    setup: SetupTest, client: AsyncClient
) -> None:
    r = await client.get("/login", allow_redirects=False)
    assert r.status_code == 400


async def test_cookie_auth_with_token(
    setup: SetupTest, client: AsyncClient
) -> None:
    """Test that cookie auth takes precedence over an Authorization header.

    JupyterHub sends an Authorization header in its internal requests with
    type token.  We want to ensure that we prefer our session cookie, rather
    than try to unsuccessfully parse that header.  Test this by completing a
    login to get a valid session and then make a request with a bogus
    Authorization header.
    """
    setup.set_github_token_response("some-code", "some-github-token")
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="org")],
    )
    setup.set_github_userinfo_response("some-github-token", userinfo)

    r = await client.get(
        "/login",
        params={"rd": "https://example.com/foo"},
        headers={"Authorization": "token some-jupyterhub-token"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        headers={"Authorization": "token some-jupyterhub-token"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == "https://example.com/foo"

    # Now make a request to the /auth endpoint with a bogus token.
    r = await client.get(
        "/auth",
        params={"scope": "read:all"},
        headers={"Authorization": "token some-jupyterhub-token"},
    )
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-Email"] == "githubuser@example.com"


async def test_claim_names(setup: SetupTest, client: AsyncClient) -> None:
    """Uses an alternate settings environment with non-default claims."""
    setup.switch_environment(
        "github", username_claim="username", uid_claim="numeric-uid"
    )
    assert setup.config.github
    setup.set_github_token_response("some-code", "some-github-token")
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="org")],
    )
    setup.set_github_userinfo_response("some-github-token", userinfo)

    r = await client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://example.com"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307

    # Check that the /auth route works and sets the headers correctly.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "githubuser"
    assert r.headers["X-Auth-Request-Uid"] == "123456"

    # Now ask for the session handle in the encrypted session to be
    # analyzed, and verify that the claims were set using our keys.
    r = await client.get("/auth/analyze")
    assert r.status_code == 200
    data = r.json()
    token_data = data["token"]["data"]
    assert token_data["username"] == "githubuser"
    assert token_data["numeric-uid"] == "123456"
    assert "uid" not in token_data
    assert "uidNumber" not in token_data


async def test_bad_redirect(setup: SetupTest, client: AsyncClient) -> None:
    setup.set_github_token_response("some-code", "some-github-token")
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[],
    )
    setup.set_github_userinfo_response("some-github-token", userinfo)

    r = await client.get(
        "/login",
        params={"rd": "https://foo.example.com/"},
        allow_redirects=False,
    )
    assert r.status_code == 400

    r = await client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://foo.example.com/"},
        allow_redirects=False,
    )
    assert r.status_code == 400

    # But if we're deployed under foo.example.com as determined by the
    # X-Forwarded-Host header, this will be allowed.
    r = await client.get(
        "/login",
        params={"rd": "https://foo.example.com/"},
        headers={
            "X-Forwarded-For": "192.168.0.1",
            "X-Forwarded-Host": "foo.example.com",
        },
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307
    assert r.headers["Location"] == "https://foo.example.com/"


async def test_github_uppercase(setup: SetupTest, client: AsyncClient) -> None:
    """Tests that usernames and organization names are forced to lowercase.

    We do not test that slugs are forced to lowercase (and do not change the
    case of slugs) because GitHub should already be coercing lowercase when
    creating the slug.
    """
    setup.set_github_token_response("some-code", "some-github-token")
    userinfo = GitHubUserInfo(
        name="A User",
        username="SomeUser",
        uid=1000,
        email="user@example.com",
        teams=[GitHubTeam(slug="a-team", gid=1000, organization="ORG")],
    )
    setup.set_github_userinfo_response("some-github-token", userinfo)

    r = await client.get(
        "/login",
        headers={"X-Auth-Request-Redirect": "https://example.com"},
        allow_redirects=False,
    )
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status_code == 307

    # The user returned by the /auth route should be forced to lowercase.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200
    assert r.headers["X-Auth-Request-User"] == "someuser"

    # Likewise for the user embedded in the token.
    r = await client.get("/auth/analyze")
    assert r.status_code == 200
    data = r.json()
    assert data["token"]["data"]["sub"] == "someuser"
    assert data["token"]["data"]["uid"] == "someuser"
