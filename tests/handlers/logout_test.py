"""Tests for the /logout route."""

from __future__ import annotations

import pytest
import respx
from _pytest.logging import LogCaptureFixture
from httpx import AsyncClient
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory
from gafaelfawr.models.github import GitHubTeam, GitHubUserInfo

from ..support.constants import TEST_HOSTNAME
from ..support.cookies import set_session_cookie
from ..support.github import mock_github
from ..support.headers import query_from_url
from ..support.logging import parse_log
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_logout(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    caplog: LogCaptureFixture,
) -> None:
    token_data = await create_session_token(factory, scopes=["read:all"])
    await set_session_cookie(client, token_data.token)

    # Confirm that we're logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200

    # Go to /logout without specifying a redirect URL.
    caplog.clear()
    r = await client.get("/logout")

    # Check the redirect and logging.
    assert r.status_code == 307
    assert r.headers["Location"] == config.after_logout_url
    assert parse_log(caplog) == [
        {
            "event": "Successful logout",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": f"https://{TEST_HOSTNAME}/logout",
                "remoteIp": "127.0.0.1",
            },
            "severity": "info",
        }
    ]

    # Confirm that we're no longer logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_with_url(client: AsyncClient, factory: Factory) -> None:
    token_data = await create_session_token(factory, scopes=["read:all"])
    await set_session_cookie(client, token_data.token)

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
    client: AsyncClient, config: Config, caplog: LogCaptureFixture
) -> None:
    caplog.clear()
    r = await client.get("/logout")

    assert r.status_code == 307
    assert r.headers["Location"] == config.after_logout_url
    assert parse_log(caplog) == [
        {
            "event": "Logout of already-logged-out session",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": f"https://{TEST_HOSTNAME}/logout",
                "remoteIp": "127.0.0.1",
            },
            "severity": "info",
        }
    ]


@pytest.mark.asyncio
async def test_logout_bad_url(
    client: AsyncClient, mock_slack: MockSlackWebhook
) -> None:
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

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []


@pytest.mark.asyncio
async def test_logout_github(
    client: AsyncClient,
    config: Config,
    respx_mock: respx.Router,
    caplog: LogCaptureFixture,
) -> None:
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
    await mock_github(respx_mock, "some-code", user_info, expect_revoke=True)
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
    assert r.headers["Location"] == config.after_logout_url
    assert parse_log(caplog) == [
        {
            "event": "Revoked GitHub OAuth authorization",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": f"https://{TEST_HOSTNAME}/logout",
                "remoteIp": "127.0.0.1",
            },
            "severity": "info",
        },
        {
            "event": "Successful logout",
            "httpRequest": {
                "requestMethod": "GET",
                "requestUrl": f"https://{TEST_HOSTNAME}/logout",
                "remoteIp": "127.0.0.1",
            },
            "severity": "info",
        },
    ]
