"""Tests for the /auth/analyze route."""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import ANY

import jwt

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.session import Session, SessionHandle

if TYPE_CHECKING:
    from tests.setup import SetupTestCallable


async def test_analyze_no_auth(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/auth/analyze")
    assert r.status == 400
    assert "Not logged in" in await r.text()


async def test_analyze_handle(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    handle = SessionHandle()
    token = setup.create_token(groups=["admin"], jti=handle.key)
    session = Session.create(handle, token)
    session_store = setup.factory.create_session_store()
    await session_store.store_session(session)

    r = await setup.client.post(
        "/auth/analyze", data={"token": handle.encode()}
    )

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


async def test_analyze_token(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    token = setup.create_token()

    r = await setup.client.post("/auth/analyze", data={"token": token.encoded})
    assert r.status == 200
    assert await r.json() == {
        "token": {
            "header": jwt.get_unverified_header(token.encoded),
            "data": token.claims,
            "valid": True,
        },
    }
