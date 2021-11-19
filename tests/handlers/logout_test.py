"""Tests for the /logout route."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gafaelfawr.providers.github import GitHubTeam, GitHubUserInfo
from tests.support.headers import query_from_url
from tests.support.logging import parse_log

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from httpx import AsyncClient

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_logout(
    client: AsyncClient, setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    token_data = await setup.create_session_token(scopes=["read:all"])
    await setup.login(client, token_data.token)

    # Confirm that we're logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200

    # Go to /logout without specifying a redirect URL.
    caplog.clear()
    r = await client.get("/logout")

    # Check the redirect and logging.
    assert r.status_code == 307
    assert r.headers["Location"] == setup.config.after_logout_url
    assert parse_log(caplog) == [
        {
            "event": "Successful logout",
            "level": "info",
            "method": "GET",
            "path": "/logout",
            "remote": "127.0.0.1",
        }
    ]

    # Confirm that we're no longer logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_with_url(client: AsyncClient, setup: SetupTest) -> None:
    token_data = await setup.create_session_token(scopes=["read:all"])
    await setup.login(client, token_data.token)

    # Confirm that we're logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200

    # Go to /logout with a redirect URL and check the redirect.
    redirect_url = "https://example.com:4444/logged-out"
    r = await client.get("/logout", params={"rd": redirect_url})
    assert r.status_code == 307
    assert r.headers["Location"] == redirect_url

    # Confirm that we're no longer logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_not_logged_in(
    client: AsyncClient, setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    caplog.clear()
    r = await client.get("/logout")

    assert r.status_code == 307
    assert r.headers["Location"] == setup.config.after_logout_url
    assert parse_log(caplog) == [
        {
            "event": "Logout of already-logged-out session",
            "level": "info",
            "method": "GET",
            "path": "/logout",
            "remote": "127.0.0.1",
        }
    ]


@pytest.mark.asyncio
async def test_logout_bad_url(client: AsyncClient, setup: SetupTest) -> None:
    r = await client.get("/logout", params={"rd": "https://foo.example.com/"})
    assert r.status_code == 422
    assert r.json() == {
        "detail": [
            {
                "loc": ["query", "rd"],
                "msg": "URL is not at example.com",
                "type": "invalid_return_url",
            }
        ]
    }


@pytest.mark.asyncio
async def test_logout_github(
    client: AsyncClient, setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    assert setup.config.github
    user_info = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[
            GitHubTeam(slug="a-team", gid=1000, organization="org"),
        ],
    )

    # Log in and log out.
    setup.set_github_response("some-code", user_info, expect_revoke=True)
    r = await client.get("/login", params={"rd": "https://example.com"})
    assert r.status_code == 307
    query = query_from_url(r.headers["Location"])
    r = await client.get(
        "/login", params={"code": "some-code", "state": query["state"][0]}
    )
    assert r.status_code == 307
    caplog.clear()
    r = await client.get("/logout")

    # Check the redirect and logging.
    assert r.status_code == 307
    assert r.headers["Location"] == setup.config.after_logout_url
    assert parse_log(caplog) == [
        {
            "event": "Revoked GitHub OAuth authorization",
            "level": "info",
            "method": "GET",
            "path": "/logout",
            "remote": "127.0.0.1",
        },
        {
            "event": "Successful logout",
            "level": "info",
            "method": "GET",
            "path": "/logout",
            "remote": "127.0.0.1",
        },
    ]
