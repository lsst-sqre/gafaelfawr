"""Tests for the ``/auth/api/v1/login`` route."""

from __future__ import annotations

import json
from unittest.mock import ANY

import pytest
from cryptography.fernet import Fernet
from httpx import AsyncClient
from safir.testing.slack import MockSlackWebhook

from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.factory import Factory
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token

from ..support.constants import TEST_HOSTNAME
from ..support.headers import assert_unauthorized_is_correct
from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_login(
    client: AsyncClient, config: Config, factory: Factory
) -> None:
    token_data = await create_session_token(
        factory, username="example", scopes={"read:all", "exec:admin"}
    )
    cookie = State(token=token_data.token).to_cookie()
    client.cookies.set(COOKIE_NAME, cookie, domain=TEST_HOSTNAME)

    r = await client.get("/auth/api/v1/login")

    assert r.status_code == 200
    data = r.json()
    expected_scopes = [
        {"name": n, "description": d}
        for n, d in sorted(config.known_scopes.items())
    ]
    assert data == {
        "csrf": ANY,
        "username": "example",
        "scopes": ["exec:admin", "read:all"],
        "config": {"scopes": expected_scopes},
    }
    state = await State.from_cookie(r.cookies[COOKIE_NAME])
    assert state.csrf == data["csrf"]
    assert state.token == token_data.token


@pytest.mark.asyncio
async def test_login_no_auth(
    client: AsyncClient,
    config: Config,
    factory: Factory,
    mock_slack: MockSlackWebhook,
) -> None:
    r = await client.get("/auth/api/v1/login")
    assert_unauthorized_is_correct(r, config)

    # An Authorization header with a valid token still redirects.
    token_data = await create_session_token(factory)
    r = await client.get(
        "/auth/api/v1/login",
        headers={"Authorization": f"bearer {token_data.token}"},
    )
    assert_unauthorized_is_correct(r, config)

    # A token with no underlying Redis representation is ignored.
    state = State(token=Token())
    client.cookies.set(COOKIE_NAME, state.to_cookie(), domain=TEST_HOSTNAME)
    r = await client.get("/auth/api/v1/login")
    assert_unauthorized_is_correct(r, config)

    # Likewise with a cookie containing a malformed token.  This requires a
    # bit more work to assemble.
    fernet = Fernet(config.session_secret.get_secret_value().encode())
    data = {"token": "bad-token"}
    bad_cookie = fernet.encrypt(json.dumps(data).encode()).decode()
    client.cookies.set(COOKIE_NAME, bad_cookie, domain=TEST_HOSTNAME)
    r = await client.get("/auth/api/v1/login")
    assert_unauthorized_is_correct(r, config)

    # And finally check with a mangled state that won't decrypt.
    bad_cookie = "XXX" + state.to_cookie()
    client.cookies.set(COOKIE_NAME, bad_cookie, domain=TEST_HOSTNAME)
    r = await client.get("/auth/api/v1/login")
    assert_unauthorized_is_correct(r, config)

    # None of these errors should have resulted in Slack alerts.
    assert mock_slack.messages == []
