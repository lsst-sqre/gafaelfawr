"""Tests for the /auth/tokens route."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from jwt_authorizer import config
from jwt_authorizer.session import Session, SessionStore, Ticket
from jwt_authorizer.tokens import Token, TokenStore
from tests.support.app import create_test_app, get_test_config
from tests.support.tokens import create_test_token

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient


async def test_tokens_no_auth(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": "foo"}
    )
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]


async def test_tokens_empty_list(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    test_config = get_test_config(app)
    token = create_test_token(test_config)
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    assert "Generate new token" in body


async def test_tokens(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    test_config = get_test_config(app)
    token = create_test_token(test_config)
    scoped_token = create_test_token(
        test_config, scope="exec:test", jti="other-token"
    )
    client = await aiohttp_client(app)
    redis_client = app["jwt_authorizer/redis"]
    token_store = TokenStore(redis_client, "uidNumber")
    pipeline = redis_client.pipeline()
    token_store.store_token(scoped_token.claims, pipeline)
    await pipeline.execute()

    r = await client.get(
        "/auth/tokens", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    assert "other-token" in body
    assert "exec:test" in body


async def test_tokens_handle_no_auth(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth/tokens/blah", headers={"X-Auth-Request-Token": "foo"}
    )
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]


async def test_tokens_handle_get_delete(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    test_config = get_test_config(app)
    token = create_test_token(test_config)
    client = await aiohttp_client(app)

    ticket = Ticket()
    scoped_token = create_test_token(
        test_config, scope="exec:test", jti=ticket.as_handle("oauth2_proxy")
    )
    session = Session(
        token=Token(encoded=scoped_token.encoded),
        email="some-user@example.com",
        user="some-user@example.com",
        created_at=datetime.now(timezone.utc),
        expires_on=datetime.now(timezone.utc) + timedelta(days=1),
    )

    redis_client = app["jwt_authorizer/redis"]
    session_store = SessionStore(
        "oauth2_proxy", test_config.session_key, redis_client
    )
    token_store = TokenStore(redis_client, "uidNumber")
    pipeline = redis_client.pipeline()
    await session_store.store_session(ticket, session, pipeline)
    token_store.store_token(scoped_token.claims, pipeline)
    await pipeline.execute()

    handle = ticket.as_handle("oauth2_proxy")
    r = await client.get(
        f"/auth/tokens/{handle}",
        headers={"X-Auth-Request-Token": token.encoded},
    )
    assert r.status == 200
    assert handle in await r.text()

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
        f"/auth/tokens/{handle}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE"},
    )
    assert r.status == 403

    # Deleting with a bogus CSRF token will fail.
    r = await client.post(
        f"/auth/tokens/{handle}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE", "_csrf": csrf_token + "xxxx"},
    )
    assert r.status == 403

    # Deleting with the correct CSRF will succeed.
    r = await client.post(
        f"/auth/tokens/{handle}",
        headers={"X-Auth-Request-Token": token.encoded},
        data={"method_": "DELETE", "_csrf": csrf_token},
    )
    assert r.status == 200
    body = await r.text()
    assert f"token with the ticket_id {handle} was deleted" in body

    assert await token_store.get_tokens("1000") == []


async def test_tokens_new_no_auth(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth/tokens/new", headers={"X-Auth-Request-Token": "foo"}
    )
    assert r.status == 401
    assert r.headers["WWW-Authenticate"]


async def test_tokens_new_form(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    test_config = get_test_config(app)
    token = create_test_token(test_config, groups=["admin"])
    client = await aiohttp_client(app)

    r = await client.get(
        "/auth/tokens/new", headers={"X-Auth-Request-Token": token.encoded}
    )
    assert r.status == 200
    body = await r.text()
    assert "exec:admin" in body
    assert "read:all" in body
    assert "admin description" in body
    assert "can read everything" in body


async def test_tokens_new_create(aiohttp_client: TestClient) -> None:
    app = await create_test_app()
    test_config = get_test_config(app)
    token = create_test_token(test_config, groups=["admin"])
    client = await aiohttp_client(app)

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
    encoded_ticket = match.group(1)

    redis_client = app["jwt_authorizer/redis"]
    token_store = TokenStore(redis_client, "uidNumber")
    tokens = await token_store.get_tokens("1000")
    assert len(tokens) == 1
    assert tokens[0] == {
        "aud": "https://example.com/",
        "email": "some-user@example.com",
        "exp": ANY,
        "iat": ANY,
        "iss": "https://test.example.com/",
        "jti": ANY,
        "scope": "read:all",
        "uid": "some-user",
        "uidNumber": "1000",
    }

    # The new token should also appear on the list we were redirected to.
    assert tokens[0]["jti"] in body

    session_store = SessionStore(
        "oauth2_proxy", test_config.session_key, redis_client
    )
    ticket = Ticket.from_str("oauth2_proxy", encoded_ticket)
    session = await session_store.get_session(ticket)
    assert session
    assert session.email == "some-user@example.com"
    assert session.user == "some-user@example.com"
    assert int(session.expires_on.timestamp()) == tokens[0]["exp"]

    decoded_token = jwt.decode(
        session.token.encoded,
        test_config.keypair.public_key_as_pem(),
        algorithms=config.ALGORITHM,
        audience="https://example.com/",
    )
    assert tokens[0] == decoded_token
