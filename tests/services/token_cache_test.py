"""Tests for the token cache dependency."""

from __future__ import annotations

from datetime import timedelta

import pytest
import structlog
from safir.datetime import current_datetime
from safir.redis import EncryptedPydanticRedisStorage

from gafaelfawr.config import Config
from gafaelfawr.factory import Factory
from gafaelfawr.models.enums import TokenType
from gafaelfawr.models.token import Token, TokenData
from gafaelfawr.storage.token import TokenRedisStore

from ..support.tokens import create_session_token


@pytest.mark.asyncio
async def test_basic(factory: Factory) -> None:
    token_data = await create_session_token(factory, scopes={"read:all"})
    token_service = factory.create_token_service()
    token_cache = factory.create_token_cache_service()
    internal_token = await token_service.get_internal_token(
        token_data, "some-service", {"read:all"}, ip_address="127.0.0.1"
    )
    notebook_token = await token_service.get_notebook_token(
        token_data, ip_address="127.0.0.1"
    )

    assert internal_token == await token_cache.get_internal_token(
        token_data, "some-service", {"read:all"}, "127.0.0.1"
    )
    assert notebook_token == await token_cache.get_notebook_token(
        token_data, "127.0.0.1"
    )

    # Requesting different internal tokens doesn't work.
    assert internal_token != await token_cache.get_internal_token(
        token_data, "other-service", {"read:all"}, "127.0.0.1"
    )
    assert notebook_token != await token_cache.get_internal_token(
        token_data, "some-service", set(), "127.0.0.1"
    )

    # A different service token for the same user requesting the same
    # information creates a different internal token.
    new_token_data = await create_session_token(factory, scopes={"read:all"})
    assert internal_token != await token_cache.get_internal_token(
        new_token_data, "some-service", {"read:all"}, "127.0.0.1"
    )
    assert notebook_token != await token_cache.get_notebook_token(
        new_token_data, "127.0.0.1"
    )

    # Changing the scope of the parent token doesn't matter as long as the
    # internal token is requested with the same scope.  Cases where the parent
    # token no longer has that scope are caught one level up by the token
    # service and thus aren't tested here.
    token_data.scopes = {"read:all", "admin:token"}
    assert internal_token == await token_cache.get_internal_token(
        token_data, "some-service", {"read:all"}, "127.0.0.1"
    )
    assert internal_token != await token_cache.get_internal_token(
        token_data, "some-service", {"admin:token"}, "127.0.0.1"
    )


@pytest.mark.asyncio
async def test_invalid(factory: Factory) -> None:
    """Invalid tokens should not be returned even if cached."""
    token_data = await create_session_token(factory, scopes={"read:all"})
    token_cache = factory.create_token_cache_service()
    internal_token = Token()
    notebook_token = Token()

    token_cache._internal_cache.store(
        token_data, "some-service", {"read:all"}, internal_token
    )
    token_cache._notebook_cache.store(token_data, notebook_token)

    assert internal_token != await token_cache.get_internal_token(
        token_data, "some-service", {"read:all"}, "127.0.0.1"
    )
    assert notebook_token != await token_cache.get_notebook_token(
        token_data, "127.0.0.1"
    )


@pytest.mark.asyncio
async def test_expiration(config: Config, factory: Factory) -> None:
    """The cache is valid until half the lifetime of the child token."""
    token_data = await create_session_token(factory, scopes={"read:all"})
    lifetime = config.token_lifetime
    now = current_datetime()
    logger = structlog.get_logger("gafaelfawr")
    storage = EncryptedPydanticRedisStorage(
        datatype=TokenData,
        redis=factory.persistent_redis,
        encryption_key=config.session_secret.get_secret_value(),
        key_prefix="token:",
    )
    slack_client = factory.create_slack_client()
    token_store = TokenRedisStore(storage, slack_client, logger)
    token_cache = factory.create_token_cache_service()

    # Store a token whose expiration is five seconds more than half the
    # typical token lifetime in the future and cache that token as an internal
    # token for our session token.
    created = now - timedelta(seconds=lifetime.total_seconds() // 2)
    expires = created + lifetime + timedelta(seconds=5)
    internal_token_data = TokenData(
        token=Token(),
        username=token_data.username,
        token_type=TokenType.internal,
        scopes={"read:all"},
        created=created,
        expires=expires,
    )
    await token_store.store_data(internal_token_data)
    token_cache._internal_cache.store(
        token_data, "some-service", {"read:all"}, internal_token_data.token
    )

    # The cache should return this token.
    assert internal_token_data.token == await token_cache.get_internal_token(
        token_data, "some-service", {"read:all"}, "127.0.0.1"
    )

    # Now change the expiration to be ten seconds earlier, which should make
    # the remaining lifetime less than half the total lifetime, and replace
    # replace the stored token with that new version.
    internal_token_data.expires = expires - timedelta(seconds=20)
    await token_store.store_data(internal_token_data)

    # The cache should now decline to return the token and generate a new one.
    old_token = internal_token_data.token
    assert old_token != await token_cache.get_internal_token(
        token_data, "some-service", {"read:all"}, "127.0.0.1"
    )

    # Do the same test with a notebook token.
    notebook_token_data = TokenData(
        token=Token(),
        username=token_data.username,
        token_type=TokenType.notebook,
        scopes={"read:all"},
        created=created,
        expires=expires,
    )
    await token_store.store_data(notebook_token_data)
    token_cache._notebook_cache.store(token_data, notebook_token_data.token)
    assert notebook_token_data.token == await token_cache.get_notebook_token(
        token_data, "127.0.0.1"
    )
    notebook_token_data.expires = expires - timedelta(seconds=20)
    await token_store.store_data(notebook_token_data)
    old_token = notebook_token_data.token
    assert old_token != await token_cache.get_notebook_token(
        token_data, "127.0.0.1"
    )
