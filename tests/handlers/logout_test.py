"""Tests for the /logout route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_logout(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    token_data = await setup.create_session_token(scopes=["read:all"])
    await setup.login(token_data.token)

    # Confirm that we're logged in.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200

    # Go to /logout without specifying a redirect URL.
    caplog.clear()
    r = await setup.client.get("/logout", allow_redirects=False)

    # Check the redirect and logging.
    assert r.status_code == 307
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
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_with_url(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(scopes=["read:all"])
    await setup.login(token_data.token)

    # Confirm that we're logged in.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 200

    # Go to /logout with a redirect URL and check the redirect.
    redirect_url = "https://example.com:4444/logged-out"
    r = await setup.client.get(
        "/logout", params={"rd": redirect_url}, allow_redirects=False
    )
    assert r.status_code == 307
    assert r.headers["Location"] == redirect_url

    # Confirm that we're no longer logged in.
    r = await setup.client.get("/auth", params={"scope": "read:all"})
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_logout_not_logged_in(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    r = await setup.client.get("/logout", allow_redirects=False)
    assert r.status_code == 307
    assert r.headers["Location"] == setup.config.after_logout_url
    data = json.loads(caplog.record_tuples[-1][2])
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


@pytest.mark.asyncio
async def test_logout_bad_url(setup: SetupTest) -> None:
    r = await setup.client.get(
        "/logout",
        params={"rd": "https://foo.example.com/"},
        allow_redirects=False,
    )
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
