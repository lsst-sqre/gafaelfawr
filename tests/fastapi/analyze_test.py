"""Tests for the ``/auth/analyze`` route."""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import urlparse

import jwt
from aiohttp import ClientSession

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.fastapi.dependencies import config, key_cache, redis
from gafaelfawr.fastapi.middleware.state import State
from gafaelfawr.session import Session, SessionHandle
from tests.support.app import create_fastapi_test_app, create_test_client
from tests.support.headers import query_from_url
from tests.support.tokens import create_test_token

if TYPE_CHECKING:
    from pathlib import Path


async def test_analyze_no_auth(tmp_path: Path) -> None:
    app = await create_fastapi_test_app(tmp_path)

    async with create_test_client(app) as client:
        r = await client.get("/auth/analyze", allow_redirects=False)

    assert r.status_code == 307
    url = urlparse(r.headers["Location"])
    assert not url.scheme
    assert not url.netloc
    assert url.path == "/login"
    assert query_from_url(r.headers["Location"]) == {
        "rd": ["https://example.com/auth/analyze"]
    }


async def test_analyze_session(tmp_path: Path) -> None:
    app = await create_fastapi_test_app(tmp_path)
    token = create_test_token(config())
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

    async with create_test_client(app) as client:
        key = config().session_secret.encode()
        r = await client.get(
            "/auth/analyze", cookies={"gafaelfawr": state.as_cookie(key)}
        )

    assert r.status_code == 200

    # Check that the result is formatted for humans.
    assert "    " in r.text
    assert '": "' in r.text

    assert r.json() == {
        "handle": {"key": ANY, "secret": ANY},
        "session": {
            "email": token.email,
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {
                "alg": ALGORITHM,
                "typ": "JWT",
                "kid": config().issuer.kid,
            },
            "data": token.claims,
            "valid": True,
        },
    }


async def test_analyze_handle(tmp_path: Path) -> None:
    app = await create_fastapi_test_app(tmp_path)
    handle = SessionHandle()

    # Handle with no session.
    async with create_test_client(app) as client:
        r = await client.post("/auth/analyze", data={"token": handle.encode()})

    assert r.status_code == 200
    assert r.json() == {
        "handle": {"key": handle.key, "secret": handle.secret},
        "errors": [f"No session found for {handle.encode()}"],
    }

    # Valid session handle.
    token = create_test_token(config(), groups=["admin"], jti=handle.key)
    session = Session.create(handle, token)
    factory = ComponentFactory(
        config=config(),
        redis=await redis(),
        key_cache=key_cache(),
        http_session=ClientSession(),
    )
    session_store = factory.create_session_store()
    await session_store.store_session(session)
    async with create_test_client(app) as client:
        r = await client.post("/auth/analyze", data={"token": handle.encode()})

    # Check that the results from /analyze include the handle, the session,
    # and the token information.
    assert r.status_code == 200
    analysis = r.json()
    assert analysis == {
        "handle": {"key": handle.key, "secret": handle.secret},
        "session": {
            "email": token.email,
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {
                "alg": ALGORITHM,
                "typ": "JWT",
                "kid": config().issuer.kid,
            },
            "data": token.claims,
            "valid": True,
        },
    }
    created_at = datetime.strptime(
        analysis["session"]["created_at"], "%Y-%m-%d %H:%M:%S %z"
    )
    expires_on = datetime.strptime(
        analysis["session"]["expires_on"], "%Y-%m-%d %H:%M:%S %z"
    )

    now = time.time()
    assert now - 5 <= created_at.timestamp() <= now + 5
    assert int(expires_on.timestamp()) == analysis["token"]["data"]["exp"]


async def test_analyze_token(tmp_path: Path) -> None:
    app = await create_fastapi_test_app(tmp_path)
    token = create_test_token(config())

    async with create_test_client(app) as client:
        r = await client.post("/auth/analyze", data={"token": token.encoded})

    assert r.status_code == 200
    assert r.json() == {
        "token": {
            "header": jwt.get_unverified_header(token.encoded),
            "data": token.claims,
            "valid": True,
        },
    }
