"""Tests for the ``/auth/api/v1/login`` route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import urlparse

import pytest
from cryptography.fernet import Fernet

from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token
from tests.support.headers import query_from_url

if TYPE_CHECKING:
    from httpx import Response

    from tests.support.setup import SetupTest


def assert_redirect_is_correct(r: Response) -> None:
    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert not url.scheme
    assert not url.netloc
    assert url.path == "/login"
    assert query_from_url(r.headers["Location"]) == {
        "rd": ["https://example.com/auth/api/v1/login"]
    }


@pytest.mark.asyncio
async def test_login(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(username="example")
    setup.login(token_data.token)

    r = await setup.client.get("/auth/api/v1/login", allow_redirects=False)

    assert r.status_code == 200
    data = r.json()
    assert data == {"csrf": ANY, "username": "example"}
    state = State.from_cookie(r.cookies[COOKIE_NAME], None)
    assert state.csrf == data["csrf"]
    assert state.token == token_data.token


@pytest.mark.asyncio
async def test_login_no_auth(setup: SetupTest) -> None:
    r = await setup.client.get("/auth/api/v1/login", allow_redirects=False)
    assert_redirect_is_correct(r)

    # An Authorization header with a valid token still redirects.
    token_data = await setup.create_session_token()
    r = await setup.client.get(
        "/auth/api/v1/login",
        headers={"Authorization": f"bearer {token_data.token}"},
        allow_redirects=False,
    )
    assert_redirect_is_correct(r)

    # A token with no underlying Redis representation is ignored.
    state = State(token=Token())
    r = await setup.client.get(
        "/auth/api/v1/login",
        cookies={COOKIE_NAME: state.as_cookie()},
        allow_redirects=False,
    )
    assert_redirect_is_correct(r)

    # Likewise with a cookie containing a malformed token.  This requires a
    # bit more work to assemble.
    key = setup.config.session_secret.encode()
    fernet = Fernet(key)
    data = {"token": "bad-token"}
    bad_cookie = fernet.encrypt(json.dumps(data).encode()).decode()
    r = await setup.client.get(
        "/auth/api/v1/login",
        cookies={COOKIE_NAME: bad_cookie},
        allow_redirects=False,
    )
    assert_redirect_is_correct(r)

    # And finally check with a mangled state that won't decrypt.
    bad_cookie = "XXX" + state.as_cookie()
    r = await setup.client.get(
        "/auth/api/v1/login",
        cookies={COOKIE_NAME: bad_cookie},
        allow_redirects=False,
    )
    assert_redirect_is_correct(r)
