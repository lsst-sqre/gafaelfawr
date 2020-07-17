"""Tests for the /auth/tokens route."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING
from unittest.mock import ANY

from gafaelfawr.session import Session, SessionHandle

if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture

    from tests.setup import SetupTestCallable


async def test_tokens_no_auth(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/auth/tokens")
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]

    data = json.loads(caplog.record_tuples[-1][2])
    assert data == {
        "event": "No authentication token found",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/tokens",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "user_agent": ANY,
    }


async def test_tokens_invalid_auth(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    setup = await create_test_setup()
    token = setup.create_token()

    r = await setup.client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": "foo"}
    )
    assert r.status == 401
    data = json.loads(caplog.record_tuples[-1][2])
    assert data == {
        "event": "Failed to authenticate token",
        "error": "Not enough segments",
        "level": "warning",
        "logger": "gafaelfawr",
        "method": "GET",
        "path": "/auth/tokens",
        "remote": "127.0.0.1",
        "request_id": ANY,
        "user_agent": ANY,
    }

    r = await setup.client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded + "xxx"}
    )
    assert r.status == 401


async def test_tokens_empty_list(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token()

    r = await setup.client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    assert "Generate new token" in body


async def test_tokens(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token()

    handle = SessionHandle()
    scoped_token = setup.create_token(scope="exec:test", jti=handle.encode())
    session = Session.create(handle, scoped_token)
    token_store = setup.factory.create_token_store()
    pipeline = setup.redis.pipeline()
    token_store.store_session(token.uid, session, pipeline)
    await pipeline.execute()

    r = await setup.client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    assert handle.key in body
    assert "exec:test" in body


async def test_tokens_handle_no_auth(
    create_test_setup: SetupTestCallable,
) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/auth/tokens/blah")
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]


async def test_tokens_handle_get_delete(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    setup = await create_test_setup()
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

    r = await setup.client.get(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
    )
    assert r.status == 200
    assert handle.key in await r.text()

    r = await setup.client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    csrf_match = re.search('name="_csrf" value="([^"]+)"', body)
    assert csrf_match
    csrf_token = csrf_match.group(1)

    # Deleting without a CSRF token will fail.
    r = await setup.client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE"},
    )
    assert r.status == 403

    # Deleting with a bogus CSRF token will fail.
    r = await setup.client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE", "_csrf": csrf_token + "xxxx"},
    )
    assert r.status == 403

    # Deleting with the correct CSRF will succeed.
    caplog.clear()
    r = await setup.client.post(
        f"/auth/tokens/{handle.key}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE", "_csrf": csrf_token},
    )
    assert r.status == 200
    body = await r.text()
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

    assert await token_store.get_tokens(token.uid) == []


async def test_tokens_new_no_auth(
    create_test_setup: SetupTestCallable,
) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/auth/tokens/new")
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]


async def test_tokens_new_form(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await setup.client.get(
        "/auth/tokens/new", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()

    for scope, description in setup.config.known_scopes.items():
        if scope in ("exec:admin", "read:all"):
            assert scope in body
            assert description in body
        else:
            assert scope not in body
            assert description not in body


async def test_tokens_new_create(
    create_test_setup: SetupTestCallable, caplog: LogCaptureFixture
) -> None:
    setup = await create_test_setup()
    token = setup.create_token(groups=["admin"], scope="exec:admin read:all")

    r = await setup.client.get(
        "/auth/tokens/new", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    csrf_match = re.search('name="_csrf" value="([^"]+)"', body)
    assert csrf_match
    csrf_token = csrf_match.group(1)

    # Creating without a CSRF token will fail.
    r = await setup.client.post(
        "/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y"},
    )
    assert r.status == 403

    # Creating with a bogus CSRF token will fail.
    r = await setup.client.post(
        "/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y", "_csrf": csrf_token + "xxxx"},
    )
    assert r.status == 403

    # Creating with a valid CSRF token will succeed.  Requesting extraneous
    # scopes that we don't have is allowed (I cannot find a way to get it to
    # fail validation), but those requested scopes will be ignored.
    caplog.clear()
    r = await setup.client.post(
        "/auth/tokens/new",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"read:all": "y", "exec:test": "y", "_csrf": csrf_token},
    )
    assert r.status == 200
    body = await r.text()
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

    token_store = setup.factory.create_token_store()
    tokens = await token_store.get_tokens(token.uid)
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
