"""Tests for the token manager class."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import pytest

from gafaelfawr.models.token import (
    Token,
    TokenData,
    TokenGroup,
    TokenInfo,
    TokenType,
    TokenUserInfo,
)

if TYPE_CHECKING:
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_token_manager(setup: SetupTest) -> None:
    token_manager = setup.factory.create_token_manager()
    token = Token()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    data = TokenData(
        secret=token.secret,
        username="example",
        token_type=TokenType.session,
        service="internal-service",
        scopes=["exec:admin", "read:all"],
        created=now,
        expires=now + timedelta(days=1),
        name="Example Person",
        uid=4137,
        groups=[
            TokenGroup(name="group", id=1000),
            TokenGroup(name="another", id=3134),
        ],
    )
    assert data.expires

    await token_manager.add(token, data, "some-token")
    data.scopes = sorted(data.scopes)
    assert await token_manager.get_data(token) == data
    assert token_manager.get_info(token) == TokenInfo(
        token=token.key,
        username=data.username,
        token_name="some-token",
        token_type=data.token_type,
        scopes=data.scopes,
        created=int(data.created.timestamp()),
        last_used=None,
        expires=int(data.expires.timestamp()),
        parent=None,
    )
    assert await token_manager.get_user_info(token) == TokenUserInfo(
        username=data.username,
        name=data.name,
        uid=data.uid,
        groups=data.groups,
    )

    assert await token_manager.get_data(Token()) is None
    assert token_manager.get_info(Token()) is None
    assert await token_manager.get_user_info(Token()) is None

    # Test that scopes are sorted when storing them in the database.
    token = Token()
    data.secret = token.secret
    data.scopes = ["read:all", "exec:admin"]
    await token_manager.add(token, data)
    assert token_manager.get_info(token) == TokenInfo(
        token=token.key,
        username=data.username,
        token_name=None,
        token_type=data.token_type,
        scopes=sorted(data.scopes),
        created=int(data.created.timestamp()),
        last_used=None,
        expires=int(data.expires.timestamp()),
        parent=None,
    )
