"""Tests for the token manager class."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from gafaelfawr.models.token import (
    TokenData,
    TokenGroup,
    TokenInfo,
    TokenType,
    TokenUserInfo,
)

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_session_token(setup: SetupTest) -> None:
    token_manager = setup.factory.create_token_manager()
    userinfo = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=4137,
        groups=[
            TokenGroup(name="group", id=1000),
            TokenGroup(name="another", id=3134),
        ],
    )

    token = await token_manager.create_session_token(userinfo)
    data = await token_manager.get_data(token)
    assert data
    assert data == TokenData(
        token=token,
        username="example",
        token_type=TokenType.session,
        scopes=[],
        created=data.created,
        expires=data.expires,
        name="Example Person",
        uid=4137,
        groups=[
            TokenGroup(name="group", id=1000),
            TokenGroup(name="another", id=3134),
        ],
    )
    now = datetime.now(tz=timezone.utc)
    assert now - timedelta(seconds=2) <= data.created <= now
    expires = data.created + timedelta(minutes=setup.config.issuer.exp_minutes)
    assert data.expires == expires

    assert token_manager.get_info(token.key) == TokenInfo(
        token=token.key,
        username=userinfo.username,
        token_name=None,
        token_type=TokenType.session,
        scopes=data.scopes,
        created=int(data.created.timestamp()),
        last_used=None,
        expires=int(data.expires.timestamp()),
        parent=None,
    )
    assert await token_manager.get_user_info(token) == userinfo

    # Test a session token with scopes.
    token = await token_manager.create_session_token(
        userinfo, scopes=["read:all", "exec:admin"]
    )
    data = await token_manager.get_data(token)
    assert data
    assert data.scopes == ["exec:admin", "read:all"]
    info = token_manager.get_info(token.key)
    assert info
    assert info.scopes == ["exec:admin", "read:all"]


@pytest.mark.asyncio
async def test_user_token(setup: SetupTest) -> None:
    userinfo = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_manager = setup.factory.create_token_manager()
    session_token = await token_manager.create_session_token(userinfo)
    data = await token_manager.get_data(session_token)
    assert data
    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=2)

    # Scopes are provided not in sorted order to ensure they're sorted when
    # creating the token.
    user_token = await token_manager.create_user_token(
        data,
        token_name="some-token",
        scopes=["read:all", "exec:admin"],
        expires=expires,
    )
    assert await token_manager.get_user_info(user_token) == userinfo
    info = token_manager.get_info(user_token.key)
    assert info
    assert info == TokenInfo(
        token=user_token.key,
        username=userinfo.username,
        token_name="some-token",
        token_type=TokenType.user,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        last_used=None,
        expires=int(expires.timestamp()),
        parent=None,
    )
    assert now - timedelta(seconds=2) <= info.created <= now
    assert await token_manager.get_data(user_token) == TokenData(
        token=user_token,
        username=userinfo.username,
        token_type=TokenType.user,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        expires=info.expires,
        name=userinfo.name,
        uid=userinfo.uid,
    )


@pytest.mark.asyncio
async def test_list(setup: SetupTest) -> None:
    userinfo = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_manager = setup.factory.create_token_manager()
    session_token = await token_manager.create_session_token(userinfo)
    data = await token_manager.get_data(session_token)
    assert data
    user_token = await token_manager.create_user_token(
        data, token_name="some-token"
    )

    session_info = token_manager.get_info(session_token.key)
    assert session_info
    user_info = token_manager.get_info(user_token.key)
    assert user_info
    assert token_manager.list_tokens(data, "example") == sorted(
        (session_info, user_info), key=lambda t: t.token
    )


@pytest.mark.asyncio
async def test_modify(setup: SetupTest) -> None:
    userinfo = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_manager = setup.factory.create_token_manager()
    session_token = await token_manager.create_session_token(userinfo)
    data = await token_manager.get_data(session_token)
    assert data
    user_token = await token_manager.create_user_token(
        data, token_name="some-token"
    )

    now = datetime.now(tz=timezone.utc).replace(microsecond=0)
    expires = now + timedelta(days=50)
    token_manager.modify_token(user_token.key, data, token_name="happy token")
    token_manager.modify_token(
        user_token.key, data, scopes=["read:all"], expires=expires
    )
    info = token_manager.get_info(user_token.key)
    assert info
    assert info == TokenInfo(
        token=user_token.key,
        username="example",
        token_type=TokenType.user,
        token_name="happy token",
        scopes=["read:all"],
        created=info.created,
        expires=expires,
        last_used=None,
        parent=None,
    )


@pytest.mark.asyncio
async def test_delete(setup: SetupTest) -> None:
    userinfo = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_manager = setup.factory.create_token_manager()
    session_token = await token_manager.create_session_token(userinfo)
    data = await token_manager.get_data(session_token)
    assert data
    token = await token_manager.create_user_token(
        data, token_name="some token"
    )

    assert await token_manager.delete_token(token.key, data)

    assert await token_manager.get_data(token) is None
    assert token_manager.get_info(token.key) is None
    assert await token_manager.get_user_info(token) is None

    assert not await token_manager.delete_token(token.key, data)
