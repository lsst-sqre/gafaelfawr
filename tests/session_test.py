"""Tests for the gafaelfawr.session package."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest
from cryptography.fernet import Fernet

from gafaelfawr.exceptions import InvalidSessionHandleException
from gafaelfawr.session import SessionHandle

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


def test_handle() -> None:
    handle = SessionHandle()
    assert handle.encode().startswith("gsh-")


def test_handle_from_str() -> None:
    bad_handles = [
        "",
        ".",
        "MLF5MB3Peg79wEC0BY8U8Q",
        "MLF5MB3Peg79wEC0BY8U8Q.",
        "gsh-",
        "gsh-.",
        "gsh-MLF5MB3Peg79wEC0BY8U8Q",
        "gsh-MLF5MB3Peg79wEC0BY8U8Q.",
        "gsh-.ChbkqEyp3EIJ2e_1Sqff3w",
        "gsh-NOT.VALID",
        "gsh-MLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w.!!!!",
        "gshMLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w",
    ]
    for handle_str in bad_handles:
        with pytest.raises(InvalidSessionHandleException):
            SessionHandle.from_str(handle_str)

    handle_str = "gsh-MLF5MB3Peg79wEC0BY8U8Q.ChbkqEyp3EIJ2e_1Sqff3w"
    handle = SessionHandle.from_str(handle_str)
    assert handle.key == "MLF5MB3Peg79wEC0BY8U8Q"
    assert handle.secret == "ChbkqEyp3EIJ2e_1Sqff3w"
    assert handle.encode() == handle_str


async def test_get_session(setup: SetupTest) -> None:
    session_store = setup.factory.create_session_store()
    expires = timedelta(days=1).total_seconds()

    # No such key.
    handle = SessionHandle()
    assert await session_store.get_session(handle) is None

    # Invalid encrypted blob.
    await setup.redis.set(f"session:{handle.key}", "foo", expire=expires)
    assert await session_store.get_session(handle) is None

    # Malformed session.
    fernet = Fernet(setup.config.session_secret.encode())
    session = fernet.encrypt(b"malformed json")
    await setup.redis.set(f"session:{handle.key}", session, expire=expires)
    assert await session_store.get_session(handle) is None

    # Mismatched secret.
    token = setup.create_token()
    data = {
        "secret": "not the right secret",
        "token": token.encoded,
        "email": token.email,
        "created_at": token.claims["iat"],
        "expires_on": token.claims["exp"],
    }
    session = fernet.encrypt(json.dumps(data).encode())
    await setup.redis.set(f"session:{handle.key}", session, expire=expires)
    assert await session_store.get_session(handle) is None

    # Token does not verify.
    token = setup.create_oidc_token(kid="some-kid")
    data = {
        "secret": handle.secret,
        "token": token.encoded,
        "email": token.email,
        "created_at": token.claims["iat"],
        "expires_on": token.claims["exp"],
    }
    session = fernet.encrypt(json.dumps(data).encode())
    await setup.redis.set(f"session:{handle.key}", session, expire=expires)
    assert await session_store.get_session(handle) is None

    # Missing required fields.
    token = setup.create_token()
    data = {
        "secret": handle.secret,
        "token": token.encoded,
        "email": token.email,
        "created_at": token.claims["iat"],
    }
    session = fernet.encrypt(json.dumps(data).encode())
    await setup.redis.set(f"session:{handle.key}", session, expire=expires)
    assert await session_store.get_session(handle) is None

    # Fix the session store and confirm we can retrieve the manually-stored
    # session.
    data["expires_on"] = token.claims["exp"]
    session = fernet.encrypt(json.dumps(data).encode())
    await setup.redis.set(f"session:{handle.key}", session, expire=expires)
    auth_session = await session_store.get_session(handle)
    assert auth_session
    assert auth_session.handle == handle
    assert auth_session.token == token
    assert auth_session.email == token.email
    created_at = datetime.fromtimestamp(token.claims["iat"], tz=timezone.utc)
    expires_on = datetime.fromtimestamp(token.claims["exp"], tz=timezone.utc)
    assert auth_session.created_at == created_at
    assert auth_session.expires_on == expires_on
