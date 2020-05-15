"""Tests for the /logout route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import parse_qs, urlparse

from gafaelfawr.providers.github import GitHubTeam, GitHubUserInfo

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from tests.setup import SetupTestCallable


async def test_logout(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    setup = await create_test_setup("github")
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[
            GitHubTeam(
                slug="a-team", gid=1000, organization="org", group_name=""
            ),
        ],
    )
    setup.set_github_userinfo(userinfo)

    # Simulate the initial authentication request.
    r = await setup.client.get(
        "/login",
        params={"rd": f"https://{setup.client.host}"},
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub, which will set the authentication
    # cookie.
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303

    # Confirm that we're logged in.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status == 200

    # Go to /logout without specifying a redirect URL and check the redirect.
    caplog.clear()
    r = await setup.client.get("/logout", allow_redirects=False)
    assert r.status == 303
    assert r.headers["Location"] == setup.config.after_logout_url
    data = json.loads(caplog.record_tuples[0][2])
    assert data == {
        "event": "Successful logout",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/logout",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "user_agent": ANY,
    }

    # Confirm that we're no longer logged in.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status == 401


async def test_logout_with_url(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup("github")
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[
            GitHubTeam(
                slug="a-team", gid=1000, organization="org", group_name=""
            ),
        ],
    )
    setup.set_github_userinfo(userinfo)

    # Simulate the initial authentication request.
    r = await setup.client.get(
        "/login",
        params={"rd": f"https://{setup.client.host}"},
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub, which will set the authentication
    # cookie.
    r = await setup.client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303

    # Confirm that we're logged in.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status == 200

    # Go to /logout with a redirect URL and check the redirect.
    redirect_url = f"https://{setup.client.host}:4444/logged-out"
    r = await setup.client.get(
        "/logout", params={"rd": redirect_url}, allow_redirects=False
    )
    assert r.status == 303
    assert r.headers["Location"] == redirect_url

    # Confirm that we're no longer logged in.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status == 401


async def test_logout_not_logged_in(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/logout", allow_redirects=False)
    assert r.status == 303
    assert r.headers["Location"] == setup.config.after_logout_url
    data = json.loads(caplog.record_tuples[0][2])
    assert data == {
        "event": "Logout of already-logged-out session",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/logout",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "user_agent": ANY,
    }

    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status == 401


async def test_logout_bad_url(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get(
        "/logout", params={"rd": "https://example.com/"}, allow_redirects=False
    )
    assert r.status == 400
