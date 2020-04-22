"""Tests for the /auth/tokens route."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from gafaelfawr.session import Session, SessionHandle
from tests.setup import SetupTest

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_tokens_no_auth(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    r = await client.get("/auth/tokens")
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]


async def test_tokens_invalid_auth(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": "foo"}
    )
    assert r.status == 403


async def test_tokens_empty_list(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token()

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    assert "Generate new token" in body


async def test_tokens(tmp_path: Path, aiohttp_client: TestClient) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token()

    handle = SessionHandle()
    scoped_token = setup.create_token(scope="exec:test", jti=handle.encode())
    session = Session.create(handle, scoped_token)
    token_store = setup.factory.create_token_store()
    pipeline = setup.redis.pipeline()
    token_store.store_session(token.uid, session, pipeline)
    await pipeline.execute()

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    assert handle.key in body
    assert "exec:test" in body


async def test_tokens_handle_no_auth(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    r = await client.get("/auth/tokens/blah")
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]


async def test_tokens_handle_get_delete(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token()

    handle = SessionHandle()
    scoped_token = setup.create_token(scope="exec:test", jti=handle.encode())
    session = Session.create(handle, scoped_token)
    session_store = setup.factory.create_session_store()
    token_store = setup.factory.create_token_store()
    pipeline = setup.redis.pipeline()
    await session_store.store_session(session, pipeline)
    token_store.store_session(token.uid, session, pipeline)
    await pipeline.execute()

    r = await client.get(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
    )
    assert r.status == 200
    assert handle.key in await r.text()

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    csrf_match = re.search('name="_csrf" value="([^"]+)"', body)
    assert csrf_match
    csrf_token = csrf_match.group(1)

    # Deleting without a CSRF token will fail.
    r = await client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE"},
    )
    assert r.status == 403

    # Deleting with a bogus CSRF token will fail.
    r = await client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE", "_csrf": csrf_token + "xxxx"},
    )
    assert r.status == 403

    # Deleting with the correct CSRF will succeed.
    r = await client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE", "_csrf": csrf_token},
    )
    assert r.status == 200
    body = await r.text()
    assert f"token with the handle {handle.key} was deleted" in body

    assert await token_store.get_tokens(token.claims["uidNumber"]) == []


async def test_tokens_new_no_auth(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    r = await client.get("/auth/tokens/new")
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]


async def test_tokens_new_form(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await client.get(
        "/auth/tokens/new", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    assert "exec:admin" in body
    assert "read:all" in body
    assert "admin description" in body
    assert "can read everything" in body


async def test_tokens_new_create(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await client.get(
        "/auth/tokens/new", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    csrf_match = re.search('name="_csrf" value="([^"]+)"', body)
    assert csrf_match
    csrf_token = csrf_match.group(1)

    # Creating without a CSRF token will fail.
    r = await client.post(
        f"/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y"},
    )
    assert r.status == 403

    # Deleting with a bogus CSRF token will fail.
    r = await client.post(
        f"/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y", "_csrf": csrf_token + "xxxx"},
    )
    assert r.status == 403

    # Creating with a valid CSRF token will succeed.
    r = await client.post(
        "/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y", "_csrf": csrf_token},
    )
    assert r.status == 200
    body = await r.text()
    assert "read:all" in body
    match = re.search(r"Token: (\S+)", body)
    assert match
    encoded_handle = match.group(1)
    handle = SessionHandle.from_str(encoded_handle)

    token_store = setup.factory.create_token_store()
    tokens = await token_store.get_tokens(token.uid)
    assert len(tokens) == 1
    assert tokens[0].key == handle.key
    assert tokens[0].scope == "read:all"
    assert tokens[0].expires

    # The new token should also appear on the list we were redirected to.
    assert tokens[0].key in body

    session_store = setup.factory.create_session_store()
    ticket = SessionHandle.from_str(encoded_handle)
    session = await session_store.get_session(ticket)
    assert session
    assert session.email == token.email
    assert int(session.token.claims["exp"]) == tokens[0].expires
