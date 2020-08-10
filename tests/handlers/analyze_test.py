"""Tests for the /auth/analyze route."""

from __future__ import annotations

import time
from datetime import datetime
from typing import TYPE_CHECKING
from unittest.mock import ANY
from urllib.parse import urlparse

import jwt

from gafaelfawr.constants import ALGORITHM
from gafaelfawr.providers.github import GitHubUserInfo
from gafaelfawr.session import Session, SessionHandle
from tests.support.headers import query_from_url

if TYPE_CHECKING:
    from tests.setup import SetupTestCallable


async def test_analyze_no_auth(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    r = await setup.client.get("/auth/analyze", allow_redirects=False)
    assert r.status == 302
    url = urlparse(r.headers["Location"])
    assert not url.scheme
    assert not url.netloc
    assert url.path == "/login"
    expected_url = setup.client.make_url("/auth/analyze")
    assert query_from_url(r.headers["Location"]) == {"rd": [str(expected_url)]}


async def test_analyze_session(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()
    userinfo = GitHubUserInfo(
        name="GitHub User",
        username="githubuser",
        uid=123456,
        email="githubuser@example.com",
        teams=[],
    )
    await setup.github_login(userinfo)

    r = await setup.client.get("/auth/analyze")
    assert r.status == 200
    analysis = await r.json()
    assert analysis == {
        "handle": {"key": ANY, "secret": ANY},
        "session": {
            "email": "githubuser@example.com",
            "created_at": ANY,
            "expires_on": ANY,
        },
        "token": {
            "header": {
                "alg": ALGORITHM,
                "typ": "JWT",
                "kid": setup.config.issuer.kid,
            },
            "data": {
                "aud": setup.config.issuer.aud,
                "email": "githubuser@example.com",
                "exp": ANY,
                "iat": ANY,
                "iss": setup.config.issuer.iss,
                "jti": ANY,
                "name": "GitHub User",
                "sub": "githubuser",
                "uid": "githubuser",
                "uidNumber": "123456",
            },
            "valid": True,
        },
    }


async def test_analyze_handle(create_test_setup: SetupTestCallable) -> None:
    setup = await create_test_setup()

    # Handle with no session.
    bad_handle = SessionHandle()
    r = await setup.client.post(
        "/auth/analyze", data={"token": bad_handle.encode()}
    )
    analysis = await r.json()
    assert analysis == {
        "handle": {"key": bad_handle.key, "secret": bad_handle.secret},
        "errors": [f"No session found for {bad_handle.encode()}"],
    }

    # Valid session handle.
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
