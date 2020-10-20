"""Tests for the /logout route."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from unittest.mock import ANY

from aiohttp import ClientSession

from gafaelfawr.dependencies import config, key_cache, redis
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.main import app
from gafaelfawr.middleware.state import State
from gafaelfawr.session import Session, SessionHandle
from tests.support.tokens import create_test_token

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.setup import SetupTest


async def test_logout(setup: SetupTest, caplog: LogCaptureFixture) -> None:
    token = create_test_token(config(), scope="read:all")
    factory = ComponentFactory(
        config=config(),
        redis=await redis(),
        key_cache=key_cache(),
        http_session=ClientSession(),
    )
    handle = SessionHandle()
    session = Session.create(handle, token)
    session_store = factory.create_session_store()
    await session_store.store_session(session)
    state = State(handle=handle)

    async with setup.async_client(app) as client:
        key = config().session_secret.encode()
        client.cookies.set(
            "gafaelfawr", state.as_cookie(key), domain="example.com"
        )

        # Confirm that we're logged in.
        r = await client.get("/auth", params={"scope": "read:all"})
        assert r.status_code == 200

        # Go to /logout without specifying a redirect URL.
        caplog.clear()
        r = await client.get("/logout", allow_redirects=False)

        # Check the redirect and logging.
        assert r.status_code == 307
        assert r.headers["Location"] == config().after_logout_url
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
        r = await client.get("/auth", params={"scope": "read:all"})
        assert r.status_code == 401


async def test_logout_with_url(setup: SetupTest) -> None:
    token = create_test_token(config(), scope="read:all")
    factory = ComponentFactory(
        config=config(),
        redis=await redis(),
        key_cache=key_cache(),
        http_session=ClientSession(),
    )
    handle = SessionHandle()
    session = Session.create(handle, token)
    session_store = factory.create_session_store()
    await session_store.store_session(session)
    state = State(handle=handle)

    async with setup.async_client(app) as client:
        key = config().session_secret.encode()
        client.cookies.set(
            "gafaelfawr", state.as_cookie(key), domain="example.com"
        )

        # Confirm that we're logged in.
        r = await client.get("/auth", params={"scope": "read:all"})
        assert r.status_code == 200

        # Go to /logout with a redirect URL and check the redirect.
        redirect_url = "https://example.com:4444/logged-out"
        r = await client.get(
            "/logout", params={"rd": redirect_url}, allow_redirects=False
        )
        assert r.status_code == 307
        assert r.headers["Location"] == redirect_url

        # Confirm that we're no longer logged in.
        r = await client.get("/auth", params={"scope": "read:all"})
        assert r.status_code == 401


async def test_logout_not_logged_in(
    setup: SetupTest, caplog: LogCaptureFixture
) -> None:
    async with setup.async_client(app) as client:
        r = await client.get("/logout", allow_redirects=False)

    assert r.status_code == 307
    assert r.headers["Location"] == config().after_logout_url
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


async def test_logout_bad_url(setup: SetupTest) -> None:
    async with setup.async_client(app) as client:
        r = await client.get(
            "/logout",
            params={"rd": "https://foo.example.com/"},
            allow_redirects=False,
        )

    assert r.status_code == 400
    assert r.json() == {
        "detail": {
            "loc": ["query", "rd"],
            "msg": "URL is not at example.com",
            "type": "bad_return_url",
        }
    }
