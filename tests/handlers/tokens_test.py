"""Tests for the /auth/tokens route."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from unittest.mock import ANY

import pytest

from gafaelfawr.session import Session, SessionHandle

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture
    from httpx import AsyncClient

    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_no_auth(setup: SetupTest, client: AsyncClient) -> None:
    for url in ("/auth/tokens", "/auth/tokens/blah", "/auth/tokens/new"):
        r = await client.get(url, allow_redirects=False)
        assert r.status_code == 401


@pytest.mark.asyncio
async def test_tokens_empty_list(
    setup: SetupTest, client: AsyncClient
) -> None:
    token = setup.create_token()
    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status_code == 200
    body = r.text
    assert "Generate new token" in body


@pytest.mark.asyncio
async def test_tokens(setup: SetupTest, client: AsyncClient) -> None:
    token = setup.create_token()
    handle = SessionHandle()
    scoped_token = setup.create_token(scope="exec:test", jti=handle.encode())
    session = Session.create(handle, scoped_token)
    user_token_store = setup.factory.create_user_token_store()
    pipeline = setup.redis.pipeline()
    user_token_store.store_session(token.uid, session, pipeline)
    await pipeline.execute()

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status_code == 200
    body = r.text
    assert handle.key in body
    assert "exec:test" in body


@pytest.mark.asyncio
async def test_tokens_handle_get_delete(
    setup: SetupTest, client: AsyncClient, caplog: LogCaptureFixture
) -> None:
    token = setup.create_token()
    handle = SessionHandle()
    scoped_token = setup.create_token(scope="exec:test", jti=handle.encode())
    session = Session.create(handle, scoped_token)
    session_store = setup.factory.create_session_store()
    user_token_store = setup.factory.create_user_token_store()
    pipeline = setup.redis.pipeline()
    await session_store.store_session(session, pipeline)
    user_token_store.store_session(token.uid, session, pipeline)
    await pipeline.execute()

    r = await client.get(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
    )
    assert r.status_code == 200
    assert handle.key in r.text

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status_code == 200
    body = r.text
    csrf_match = re.search('name="_csrf" value="([^"]+)"', body)
    assert csrf_match
    csrf_token = csrf_match.group(1)

    # Deleting without a CSRF token will fail.
    r = await client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE"},
    )
    assert r.status_code == 400

    # Deleting with a bogus CSRF token will fail.
    r = await client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE", "_csrf": csrf_token + "xxxx"},
    )
    assert r.status_code == 400

    # Deleting with the correct CSRF will succeed.
    caplog.clear()
    r = await client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE", "_csrf": csrf_token},
    )
    assert r.status_code == 200
    body = r.text
    assert f"token with the handle {handle.key} was deleted" in body
    data = json.loads(caplog.record_tuples[0][2])
    assert data == {
        "event": f"Deleted token {handle.key}",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "POST",
        "path": f"/auth/tokens/{handle.key}",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "scope": " ".join(sorted(token.scope)),
        "token": token.jti,
        "user": token.username,
        "user_agent": ANY,
    }

    assert await user_token_store.get_tokens(token.uid) == []


@pytest.mark.asyncio
async def test_tokens_new_form(setup: SetupTest, client: AsyncClient) -> None:
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await client.get(
        "/auth/tokens/new",
        headers={"Authorization": f"bearer {token.encoded}"},
    )

    assert r.status_code == 200
    body = r.text
    for scope, description in setup.config.known_scopes.items():
        if scope in ("exec:admin", "read:all"):
            assert scope in body
            assert description in body
        else:
            assert scope not in body
            assert description not in body


@pytest.mark.asyncio
async def test_tokens_new_create(
    setup: SetupTest, client: AsyncClient, caplog: LogCaptureFixture
) -> None:
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await client.get(
        "/auth/tokens/new", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status_code == 200
    body = r.text
    csrf_match = re.search('name="_csrf" value="([^"]+)"', body)
    assert csrf_match
    csrf_token = csrf_match.group(1)

    # Creating without a CSRF token will fail.
    r = await client.post(
        "/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y"},
    )
    assert r.status_code == 400

    # Creating with a bogus CSRF token will fail.
    r = await client.post(
        "/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y", "_csrf": csrf_token + "xxxx"},
    )
    assert r.status_code == 400

    # Creating with a valid CSRF token will succeed.  Requesting
    # extraneous scopes that we don't have is allowed (I cannot find a way
    # to get it to fail validation), but those requested scopes will be
    # ignored.
    caplog.clear()
    r = await client.post(
        "/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y", "exec:test": "y", "_csrf": csrf_token},
    )
    assert r.status_code == 200
    body = r.text
    assert "read:all" in body
    match = re.search(r"Token: (\S+)", body)
    assert match
    encoded_handle = match.group(1)
    handle = SessionHandle.from_str(encoded_handle)

    data = json.loads(caplog.record_tuples[0][2])
    assert data == {
        "event": f"Created token {handle.key} with scope read:all",
        "level": "info",
        "logger": "gafaelfawr",
        "method": "POST",
        "path": "/auth/tokens/new",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "scope": " ".join(sorted(token.scope)),
        "token": token.jti,
        "user": token.username,
        "user_agent": ANY,
    }

    user_token_store = setup.factory.create_user_token_store()
    tokens = await user_token_store.get_tokens(token.uid)
    assert len(tokens) == 1
    assert tokens[0].key == handle.key
    assert tokens[0].scope == "read:all"
    assert tokens[0].expires

    # The new token should also appear on the list we were redirected to.
    assert tokens[0].key in body

    session_store = setup.factory.create_session_store()
    handle = SessionHandle.from_str(encoded_handle)
    session = await session_store.get_session(handle)
    assert session
    assert session.email == token.email
    assert int(session.token.claims["exp"]) == tokens[0].expires
