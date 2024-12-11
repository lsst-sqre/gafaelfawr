"""Tests for the token storage layer."""

import pytest

from gafaelfawr.factory import Factory
from gafaelfawr.storage.token import TokenDatabaseStore

from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_metrics(factory: Factory) -> None:
    token_db_store = TokenDatabaseStore(factory.session)

    async with factory.session.begin():
        assert await token_db_store.count_unique_sessions() == 0
    await create_session_token(factory, username="someuser")
    await create_session_token(factory, username="otheruser")
    token_data = await create_session_token(factory, username="someuser")
    async with factory.session.begin():
        assert await token_db_store.count_unique_sessions() == 2

    async with factory.session.begin():
        assert await token_db_store.count_user_tokens() == 0
    token_service = factory.create_token_service()
    await token_service.create_user_token(
        token_data,
        "someuser",
        token_name="some-token",
        scopes=set(),
        ip_address="192.168.0.1",
    )
    async with factory.session.begin():
        assert await token_db_store.count_user_tokens() == 1
