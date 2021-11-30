"""Tests for the token cache dependency."""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest

from gafaelfawr.models.token import Token, TokenData, TokenType
from gafaelfawr.storage.base import RedisStorage
from gafaelfawr.storage.token import TokenRedisStore
from gafaelfawr.util import current_datetime

if TYPE_CHECKING:
    from gafaelfawr.config import Config
    from tests.support.setup import SetupTest


@pytest.mark.asyncio
async def test_basic(setup: SetupTest) -> None:
    token_data = await setup.create_session_token(scopes=["read:all"])
    token_service = setup.factory.create_token_service()
    token_cache = setup.factory.create_token_cache_service()
    internal_token = await token_service.get_internal_token(
        token_data, "some-service", ["read:all"], ip_address="127.0.0.1"
    )
    notebook_token = await token_service.get_notebook_token(
        token_data, ip_address="127.0.0.1"
    )

    assert internal_token == await token_cache.get_internal_token(
        token_data, "some-service", ["read:all"], "127.0.0.1"
    )
    assert notebook_token == await token_cache.get_notebook_token(
        token_data, "127.0.0.1"
    )

    # Requesting different internal tokens doesn't work.
    assert internal_token != await token_cache.get_internal_token(
        token_data, "other-service", ["read:all"], "127.0.0.1"
    )
    assert notebook_token != await token_cache.get_internal_token(
        token_data, "some-service", [], "127.0.0.1"
    )

    # A different service token for the same user requesting the same
    # information creates a different internal token.
    new_token_data = await setup.create_session_token(scopes=["read:all"])
    assert internal_token != await token_cache.get_internal_token(
        new_token_data, "some-service", ["read:all"], "127.0.0.1"
    )
    assert notebook_token != await token_cache.get_notebook_token(
        new_token_data, "127.0.0.1"
    )

    # Changing the scope of the parent token doesn't matter as long as the
    # internal token is requested with the same scope.  Cases where the parent
    # token no longer has that scope are caught one level up by the token
    # service and thus aren't tested here.
    token_data.scopes = ["read:all", "admin:token"]
    assert internal_token == await token_cache.get_internal_token(
        token_data, "some-service", ["read:all"], "127.0.0.1"
    )
    assert internal_token != await token_cache.get_internal_token(
        token_data, "some-service", ["admin:token"], "127.0.0.1"
    )


@pytest.mark.asyncio
async def test_invalid(setup: SetupTest) -> None:
    """Invalid tokens should not be returned even if cached."""
    token_data = await setup.create_session_token(scopes=["read:all"])
    token_cache = setup.factory.create_token_cache_service()
    internal_token = Token()
    notebook_token = Token()

    token_cache.store_internal_token(
        internal_token, token_data, "some-service", ["read:all"]
    )
    token_cache.store_notebook_token(notebook_token, token_data)

    assert internal_token != await token_cache.get_internal_token(
        token_data, "some-service", ["read:all"], "127.0.0.1"
    )
    assert notebook_token != await token_cache.get_notebook_token(
        token_data, "127.0.0.1"
    )


@pytest.mark.asyncio
async def test_expiration(config: Config, setup: SetupTest) -> None:
    """The cache is valid until half the lifetime of the child token."""
    token_data = await setup.create_session_token(scopes=["read:all"])
    lifetime = config.token_lifetime
    now = current_datetime()
    storage = RedisStorage(TokenData, config.session_secret, setup.redis)
    token_store = TokenRedisStore(storage, setup.logger)
    token_cache = setup.factory.create_token_cache_service()

    # Store a token whose expiration is five seconds more than half the
    # typical token lifetime in the future and cache that token as an internal
    # token for our session token.
    created = now - timedelta(seconds=lifetime.total_seconds() // 2)
    expires = created + lifetime + timedelta(seconds=5)
    internal_token_data = TokenData(
        token=Token(),
        username=token_data.username,
        token_type=TokenType.internal,
        scopes=["read:all"],
        created=created,
        expires=expires,
    )
    await token_store.store_data(internal_token_data)
    token_cache.store_internal_token(
        internal_token_data.token, token_data, "some-service", ["read:all"]
    )

    # The cache should return this token.
    assert internal_token_data.token == await token_cache.get_internal_token(
        token_data, "some-service", ["read:all"], "127.0.0.1"
    )

    # Now change the expiration to be ten seconds earlier, which should make
    # the remaining lifetime less than half the total lifetime, and replace
    # replace the stored token with that new version.
    internal_token_data.expires = expires - timedelta(seconds=20)
    await token_store.store_data(internal_token_data)

    # The cache should now decline to return the token and generate a new one.
    assert internal_token_data.token != await token_cache.get_internal_token(
        token_data, "some-service", ["read:all"], "127.0.0.1"
    )

    # Do the same test with a notebook token.
    notebook_token_data = TokenData(
        token=Token(),
        username=token_data.username,
        token_type=TokenType.notebook,
        scopes=["read:all"],
        created=created,
        expires=expires,
    )
    await token_store.store_data(notebook_token_data)
    token_cache.store_notebook_token(notebook_token_data.token, token_data)
    assert notebook_token_data.token == await token_cache.get_notebook_token(
        token_data, "127.0.0.1"
    )
    notebook_token_data.expires = expires - timedelta(seconds=20)
    await token_store.store_data(notebook_token_data)
    assert notebook_token_data.token != await token_cache.get_notebook_token(
        token_data, "127.0.0.1"
    )
