"""Tests for the /auth/analyze route."""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from jwt_authorizer.constants import ALGORITHM
from jwt_authorizer.session import Session, SessionHandle
from tests.setup import SetupTest

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_analyze_ticket(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    handle = SessionHandle()
    token = setup.create_token(groups=["admin"], jti=handle.key)
    session = Session.create(handle, token)
    session_store = setup.factory.create_session_store()
    await session_store.store_session(session)

    r = await client.post("/auth/analyze", data={"token": handle.encode()})

    # Check that the results from /analyze include the handle, the session,
    # and the token information.
    assert r.status == 200
    analysis = await r.json()
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
                "kid": setup.config.issuer.kid,
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


async def test_analyze_token(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)
    token = setup.create_token()

    r = await client.post("/auth/analyze", data={"token": token.encoded})
    assert r.status == 200
    assert await r.json() == {
        "token": {
            "header": jwt.get_unverified_header(token.encoded),
            "data": token.claims,
            "valid": True,
        },
    }
