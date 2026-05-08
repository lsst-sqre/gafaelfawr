"""Tests for errors in the ``/ingress/auth`` route."""

import pytest
from httpx import AsyncClient

from gafaelfawr.factory import Factory
from gafaelfawr.storage.token import TokenDatabaseStore

from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_database_desync(client: AsyncClient, factory: Factory) -> None:
    """Test error handling when a token is missing from the database.

    If a token exists only in Redis but not in the database, internal tokens
    cannot be generated for it. Test error handling in that case.
    """
    token_data = await create_session_token(factory, scopes={"read:all"})
    token_store = TokenDatabaseStore(factory.session)
    async with factory.session.begin():
        assert await token_store.delete(token_data.token.key)

    # Authentication with an internal token requested should return a 401.
    r = await client.get(
        "/ingress/auth",
        params={
            "scope": "read:all",
            "service": "test",
            "delegate_to": "test",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 401

    # Likewise for a notebook token.
    r = await client.get(
        "/ingress/auth",
        params={
            "scope": "read:all",
            "service": "test",
            "notebook": "true",
        },
        headers={"Authorization": f"Bearer {token_data.token}"},
    )
    assert r.status_code == 401
