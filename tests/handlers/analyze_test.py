"""Tests for the /auth/analyze route."""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from jwt_authorizer.constants import ALGORITHM
from jwt_authorizer.session import Session, SessionHandle
from tests.support.app import (
    create_test_app,
    get_test_config,
    get_test_factory,
)
from tests.support.tokens import create_test_token

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_analyze_ticket(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    app = await create_test_app(tmp_path)
    test_config = get_test_config(app)
    test_factory = get_test_factory(app)
    client = await aiohttp_client(app)

    handle = SessionHandle()
    token = create_test_token(test_config, groups=["admin"], jti=handle.key)
    session = Session.create(handle, token)
    session_store = test_factory.create_session_store()
    await session_store.store_session(session)

    r = await client.post("/auth/analyze", data={"token": handle.encode()},)

    # Check that the results from /analyze include the handle, the session,
    # and the token information.
    assert r.status == 200
    analysis = await r.json()
    assert analysis == {
        "handle": {"key": handle.key, "secret": handle.secret},
        "session": {
            "email": "some-user@example.com",
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {"alg": ALGORITHM, "typ": "JWT", "kid": "some-kid"},
            "data": {
                "aud": "https://example.com/",
                "email": "some-user@example.com",
                "exp": ANY,
                "iat": ANY,
                "isMemberOf": [{"name": "admin"}],
                "iss": "https://test.example.com/",
                "jti": handle.key,
                "sub": "some-user",
                "uid": "some-user",
                "uidNumber": "1000",
            },
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


async def test_analyze_token(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    app = await create_test_app(tmp_path)
    test_config = get_test_config(app)
    token = create_test_token(test_config)
    client = await aiohttp_client(app)

    r = await client.post("/auth/analyze", data={"token": token.encoded})
    assert r.status == 200
    assert await r.json() == {
        "token": {
            "header": jwt.get_unverified_header(token.encoded),
            "data": token.claims,
            "valid": True,
        },
    }
