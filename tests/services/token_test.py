"""Tests for the token service class."""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from pydantic import ValidationError

from gafaelfawr.config import Config
from gafaelfawr.dependencies.redis import redis_dependency
from gafaelfawr.exceptions import (
    InvalidExpiresError,
    InvalidScopesError,
    PermissionDeniedError,
)
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.models.history import TokenChange, TokenChangeHistoryEntry
from gafaelfawr.models.token import (
    AdminTokenRequest,
    Token,
    TokenData,
    TokenGroup,
    TokenInfo,
    TokenType,
    TokenUserInfo,
)
from gafaelfawr.util import current_datetime
from tests.support.tokens import create_session_token
from tests.support.util import assert_is_now


@pytest.mark.asyncio
async def test_session_token(
    config: Config, factory: ComponentFactory
) -> None:
    token_service = factory.create_token_service()
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=4137,
        groups=[
            TokenGroup(name="group", id=1000),
            TokenGroup(name="another", id=3134),
        ],
    )

    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info, scopes=["user:token"], ip_address="127.0.0.1"
        )
    data = await token_service.get_data(token)
    assert data and data == TokenData(
        token=token,
        username="example",
        token_type=TokenType.session,
        scopes=["user:token"],
        created=data.created,
        expires=data.expires,
        name="Example Person",
        uid=4137,
        groups=[
            TokenGroup(name="group", id=1000),
            TokenGroup(name="another", id=3134),
        ],
    )
    assert_is_now(data.created)
    expires = data.created + timedelta(minutes=config.issuer.exp_minutes)
    assert data.expires == expires

    async with factory.session.begin():
        info = await token_service.get_token_info_unchecked(token.key)
    assert info and info == TokenInfo(
        token=token.key,
        username=user_info.username,
        token_name=None,
        token_type=TokenType.session,
        scopes=data.scopes,
        created=int(data.created.timestamp()),
        last_used=None,
        expires=int(data.expires.timestamp()),
        parent=None,
    )
    assert await token_service.get_user_info(token) == user_info

    async with factory.session.begin():
        history = await token_service.get_change_history(
            data, token=token.key, username=data.username
        )
    assert history.entries == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.session,
            scopes=["user:token"],
            expires=data.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_time=data.created,
        )
    ]

    # Test a session token with scopes.
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "exec:admin"],
            ip_address="127.0.0.1",
        )
        data = await token_service.get_data(token)
        assert data and data.scopes == ["exec:admin", "read:all"]
        info = await token_service.get_token_info_unchecked(token.key)
        assert info and info.scopes == ["exec:admin", "read:all"]


@pytest.mark.asyncio
async def test_user_token(factory: ComponentFactory) -> None:
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "exec:admin", "user:token"],
            ip_address="127.0.0.1",
        )
    data = await token_service.get_data(session_token)
    assert data
    expires = current_datetime() + timedelta(days=2)

    # Scopes are provided not in sorted order to ensure they're sorted when
    # creating the token.
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            data,
            "example",
            token_name="some-token",
            scopes=["read:all", "exec:admin"],
            expires=expires,
            ip_address="192.168.0.1",
        )
        assert await token_service.get_user_info(user_token) == user_info
        info = await token_service.get_token_info_unchecked(user_token.key)
    assert info and info == TokenInfo(
        token=user_token.key,
        username=user_info.username,
        token_name="some-token",
        token_type=TokenType.user,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        last_used=None,
        expires=int(expires.timestamp()),
        parent=None,
    )
    assert_is_now(info.created)
    assert await token_service.get_data(user_token) == TokenData(
        token=user_token,
        username=user_info.username,
        token_type=TokenType.user,
        scopes=["exec:admin", "read:all"],
        created=info.created,
        expires=info.expires,
        name=user_info.name,
        uid=user_info.uid,
    )

    async with factory.session.begin():
        history = await token_service.get_change_history(
            data, token=user_token.key, username=data.username
        )
    assert history.entries == [
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="some-token",
            scopes=["exec:admin", "read:all"],
            expires=info.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address="192.168.0.1",
            event_time=info.created,
        )
    ]


@pytest.mark.asyncio
async def test_notebook_token(
    config: Config, factory: ComponentFactory
) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=4137,
        groups=[TokenGroup(name="foo", id=1000)],
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "exec:admin", "user:token"],
            ip_address="127.0.0.1",
        )
    data = await token_service.get_data(session_token)
    assert data

    async with factory.session.begin():
        token = await token_service.get_notebook_token(
            data, ip_address="1.0.0.1"
        )
        assert await token_service.get_user_info(token) == user_info
        info = await token_service.get_token_info_unchecked(token.key)
    assert info and info == TokenInfo(
        token=token.key,
        username=user_info.username,
        token_type=TokenType.notebook,
        scopes=["exec:admin", "read:all", "user:token"],
        created=info.created,
        last_used=None,
        expires=data.expires,
        parent=session_token.key,
    )
    assert_is_now(info.created)
    assert await token_service.get_data(token) == TokenData(
        token=token,
        username=user_info.username,
        token_type=TokenType.notebook,
        scopes=["exec:admin", "read:all", "user:token"],
        created=info.created,
        expires=data.expires,
        name=user_info.name,
        uid=user_info.uid,
        groups=user_info.groups,
    )

    # Creating another notebook token from the same parent token just returns
    # the same notebook token as before.
    new_token = await token_service.get_notebook_token(
        data, ip_address="127.0.0.1"
    )
    assert token == new_token

    # Try again with the cache cleared to force a database lookup.
    await token_service._token_cache.clear()
    async with factory.session.begin():
        new_token = await token_service.get_notebook_token(
            data, ip_address="127.0.0.1"
        )
    assert token == new_token

    async with factory.session.begin():
        history = await token_service.get_change_history(
            data, token=token.key, username=data.username
        )
    assert history.entries == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.notebook,
            parent=data.token.key,
            scopes=["exec:admin", "read:all", "user:token"],
            expires=data.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address="1.0.0.1",
            event_time=info.created,
        )
    ]

    # It's possible we'll have a race condition where two workers both create
    # an notebook token at the same time with the same parameters.  Gafaelfawr
    # 3.0.2 had a regression where, once that had happened, it could not
    # retrieve the notebook token because it didn't expect multiple results
    # from the query.  Simulate this and make sure it's handled properly.  The
    # easiest way to do this is to use the internals of the token service.
    second_token = Token()
    notebook_token_data = TokenData(
        token=second_token,
        username=data.username,
        token_type=TokenType.notebook,
        scopes=["exec:admin", "read:all", "user:token"],
        created=info.created,
        expires=data.expires,
        name=data.name,
        email=data.email,
        uid=data.uid,
        groups=data.groups,
    )
    await token_service._token_redis_store.store_data(notebook_token_data)
    async with factory.session.begin():
        await token_service._token_db_store.add(
            notebook_token_data, parent=data.token.key
        )
    await token_service._token_cache.clear()
    async with factory.session.begin():
        dup_notebook_token = await token_service.get_notebook_token(
            data, ip_address="127.0.0.1"
        )
    assert dup_notebook_token in (token, second_token)

    # Check that the expiration time is capped by creating a user token that
    # doesn't expire and then creating a notebook token from it.
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            data,
            data.username,
            token_name="some token",
            scopes=[],
            expires=None,
            ip_address="127.0.0.1",
        )
    data = await token_service.get_data(user_token)
    assert data
    async with factory.session.begin():
        new_token = await token_service.get_notebook_token(
            data, ip_address="127.0.0.1"
        )
        assert new_token != token
        info = await token_service.get_token_info_unchecked(new_token.key)
    assert info
    expires = info.created + timedelta(minutes=config.issuer.exp_minutes)
    assert info.expires == expires


@pytest.mark.asyncio
async def test_internal_token(
    config: Config, factory: ComponentFactory
) -> None:
    user_info = TokenUserInfo(
        username="example",
        name="Example Person",
        uid=4137,
        groups=[TokenGroup(name="foo", id=1000)],
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "exec:admin", "user:token"],
            ip_address="127.0.0.1",
        )
    data = await token_service.get_data(session_token)
    assert data

    async with factory.session.begin():
        internal_token = await token_service.get_internal_token(
            data,
            service="some-service",
            scopes=["read:all"],
            ip_address="2001:db8::45",
        )
        assert await token_service.get_user_info(internal_token) == user_info
        info = await token_service.get_token_info_unchecked(internal_token.key)
    assert info and info == TokenInfo(
        token=internal_token.key,
        username=user_info.username,
        token_type=TokenType.internal,
        service="some-service",
        scopes=["read:all"],
        created=info.created,
        last_used=None,
        expires=data.expires,
        parent=session_token.key,
    )
    assert_is_now(info.created)

    # Cannot request a scope that the parent token doesn't have.
    with pytest.raises(InvalidScopesError):
        await token_service.get_internal_token(
            data,
            service="some-service",
            scopes=["read:some"],
            ip_address="127.0.0.1",
        )

    # Creating another internal token from the same parent token with the same
    # parameters just returns the same internal token as before.
    new_internal_token = await token_service.get_internal_token(
        data,
        service="some-service",
        scopes=["read:all"],
        ip_address="127.0.0.1",
    )
    assert internal_token == new_internal_token

    # Try again with the cache cleared to force a database lookup.
    await token_service._token_cache.clear()
    async with factory.session.begin():
        new_internal_token = await token_service.get_internal_token(
            data,
            service="some-service",
            scopes=["read:all"],
            ip_address="127.0.0.1",
        )
    assert internal_token == new_internal_token

    async with factory.session.begin():
        history = await token_service.get_change_history(
            data, token=internal_token.key, username=data.username
        )
    assert history.entries == [
        TokenChangeHistoryEntry(
            token=internal_token.key,
            username=data.username,
            token_type=TokenType.internal,
            parent=data.token.key,
            service="some-service",
            scopes=["read:all"],
            expires=data.expires,
            actor=data.username,
            action=TokenChange.create,
            ip_address="2001:db8::45",
            event_time=info.created,
        )
    ]

    # It's possible we'll have a race condition where two workers both create
    # an internal token at the same time with the same parameters.  Gafaelfawr
    # 3.0.2 had a regression where, once that had happened, it could not
    # retrieve the internal token because it didn't expect multiple results
    # from the query.  Simulate this and make sure it's handled properly.  The
    # easiest way to do this is to use the internals of the token service.
    second_internal_token = Token()
    created = current_datetime()
    expires = created + config.token_lifetime
    internal_token_data = TokenData(
        token=second_internal_token,
        username=data.username,
        token_type=TokenType.internal,
        scopes=["read:all"],
        created=created,
        expires=expires,
        name=data.name,
        email=data.email,
        uid=data.uid,
        groups=data.groups,
    )
    await token_service._token_redis_store.store_data(internal_token_data)
    async with factory.session.begin():
        await token_service._token_db_store.add(
            internal_token_data, service="some-service", parent=data.token.key
        )
    await token_service._token_cache.clear()
    async with factory.session.begin():
        dup_internal_token = await token_service.get_internal_token(
            data,
            service="some-service",
            scopes=["read:all"],
            ip_address="127.0.0.1",
        )
    assert dup_internal_token in (internal_token, second_internal_token)

    # A different scope or a different service results in a new token.
    async with factory.session.begin():
        new_internal_token = await token_service.get_internal_token(
            data,
            service="some-service",
            scopes=["exec:admin"],
            ip_address="127.0.0.1",
        )
    assert internal_token != new_internal_token
    async with factory.session.begin():
        new_internal_token = await token_service.get_internal_token(
            data,
            service="another-service",
            scopes=["read:all"],
            ip_address="127.0.0.1",
        )
    assert internal_token != new_internal_token

    # Check that the expiration time is capped by creating a user token that
    # doesn't expire and then creating a notebook token from it.  Use this to
    # test a token with empty scopes.
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            data,
            data.username,
            token_name="some token",
            scopes=["exec:admin"],
            expires=None,
            ip_address="127.0.0.1",
        )
    data = await token_service.get_data(user_token)
    assert data
    async with factory.session.begin():
        new_internal_token = await token_service.get_internal_token(
            data, service="some-service", scopes=[], ip_address="127.0.0.1"
        )
        assert new_internal_token != internal_token
        info = await token_service.get_token_info_unchecked(
            new_internal_token.key
        )
    assert info and info.scopes == []
    expires = info.created + timedelta(minutes=config.issuer.exp_minutes)
    assert info.expires == expires


@pytest.mark.asyncio
async def test_child_token_lifetime(
    config: Config, factory: ComponentFactory
) -> None:
    """Test that a new internal token is generated at half its lifetime."""
    session_token_data = await create_session_token(factory)
    token_service = factory.create_token_service()

    # Generate a user token with a lifetime less than half of the default
    # lifetime for an internal token.  This will get us a short-lived internal
    # token that should be ineligible for handing out for a user token that
    # doesn't expire.
    delta = timedelta(minutes=(config.issuer.exp_minutes / 2) - 5)
    expires = current_datetime() + delta
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            session_token_data,
            session_token_data.username,
            token_name="n",
            expires=expires,
            scopes=[],
            ip_address="127.0.0.1",
        )
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data

    # Get an internal token and ensure we get the same one when we ask again.
    async with factory.session.begin():
        internal_token = await token_service.get_internal_token(
            user_token_data, service="a", scopes=[], ip_address="127.0.0.1"
        )
    internal_token_data = await token_service.get_data(internal_token)
    assert internal_token_data
    assert internal_token_data.expires == user_token_data.expires
    new_internal_token = await token_service.get_internal_token(
        user_token_data, service="a", scopes=[], ip_address="127.0.0.1"
    )
    assert new_internal_token == internal_token

    # Do the same thing with a notebook token.
    async with factory.session.begin():
        notebook_token = await token_service.get_notebook_token(
            user_token_data, ip_address="127.0.0.1"
        )
    notebook_token_data = await token_service.get_data(notebook_token)
    assert notebook_token_data
    assert notebook_token_data.expires == user_token_data.expires
    new_notebook_token = await token_service.get_notebook_token(
        user_token_data, ip_address="127.0.0.1"
    )
    assert new_notebook_token == notebook_token

    # Change the expiration of the user token to longer than the maximum
    # internal token lifetime.
    new_delta = timedelta(minutes=config.issuer.exp_minutes * 2)
    expires = current_datetime() + new_delta
    async with factory.session.begin():
        assert await token_service.modify_token(
            user_token.key,
            session_token_data,
            session_token_data.username,
            ip_address="127.0.0.1",
            expires=expires,
        )
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data

    # Now, request an internal and notebook token.  We should get different
    # ones with a longer expiration.
    async with factory.session.begin():
        new_internal_token = await token_service.get_internal_token(
            user_token_data, service="a", scopes=[], ip_address="127.0.0.1"
        )
    assert new_internal_token != internal_token
    internal_token = new_internal_token
    internal_token_data = await token_service.get_data(internal_token)
    assert internal_token_data
    delta = timedelta(minutes=config.issuer.exp_minutes)
    assert internal_token_data.expires == internal_token_data.created + delta
    async with factory.session.begin():
        new_notebook_token = await token_service.get_notebook_token(
            user_token_data, ip_address="127.0.0.1"
        )
    assert new_notebook_token != notebook_token
    notebook_token = new_notebook_token
    notebook_token_data = await token_service.get_data(notebook_token)
    assert notebook_token_data
    assert notebook_token_data.expires == notebook_token_data.created + delta

    # Change the expiration of the user token to no longer expire.
    async with factory.session.begin():
        assert await token_service.modify_token(
            user_token.key,
            session_token_data,
            session_token_data.username,
            ip_address="127.0.0.1",
            expires=None,
            no_expire=True,
        )
    user_token_data = await token_service.get_data(user_token)
    assert user_token_data

    # Get an internal and notebook token again.  We should get the same ones
    # as last time.
    new_internal_token = await token_service.get_internal_token(
        user_token_data, service="a", scopes=[], ip_address="127.0.0.1"
    )
    assert new_internal_token == internal_token
    new_notebook_token = await token_service.get_notebook_token(
        user_token_data, ip_address="127.0.0.1"
    )
    assert new_notebook_token == notebook_token


@pytest.mark.asyncio
async def test_token_from_admin_request(factory: ComponentFactory) -> None:
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_session_token(
            user_info, scopes=[], ip_address="127.0.0.1"
        )
    data = await token_service.get_data(token)
    assert data
    expires = current_datetime() + timedelta(days=2)
    request = AdminTokenRequest(
        username="otheruser",
        token_type=TokenType.user,
        token_name="some token",
        scopes=["read:all"],
        expires=expires,
        name="Other User",
        uid=1345,
        groups=[TokenGroup(name="some-group", id=4133)],
    )

    # Cannot create a token via admin request because the authentication
    # information is missing the admin:token scope.
    with pytest.raises(PermissionDeniedError):
        await token_service.create_token_from_admin_request(
            request, data, ip_address="127.0.0.1"
        )

    # Get a token with an appropriate scope.
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info, scopes=["admin:token"], ip_address="127.0.0.1"
        )
    admin_data = await token_service.get_data(session_token)
    assert admin_data

    # Test a few more errors.
    request.scopes = ["bogus:scope"]
    with pytest.raises(InvalidScopesError):
        await token_service.create_token_from_admin_request(
            request, admin_data, ip_address="127.0.0.1"
        )
    request.scopes = ["read:all"]
    request.expires = current_datetime()
    with pytest.raises(InvalidExpiresError):
        await token_service.create_token_from_admin_request(
            request, admin_data, ip_address="127.0.0.1"
        )
    request.expires = expires

    # Try a successful request.
    async with factory.session.begin():
        token = await token_service.create_token_from_admin_request(
            request, admin_data, ip_address="127.0.0.1"
        )
    user_data = await token_service.get_data(token)
    assert user_data and user_data == TokenData(
        token=token, created=user_data.created, **request.dict()
    )
    assert_is_now(user_data.created)

    async with factory.session.begin():
        history = await token_service.get_change_history(
            admin_data, token=token.key, username=request.username
        )
    assert history.entries == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=request.username,
            token_type=TokenType.user,
            token_name=request.token_name,
            scopes=["read:all"],
            expires=request.expires,
            actor=admin_data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_time=user_data.created,
        )
    ]

    # Non-admins can't see other people's tokens.
    with pytest.raises(PermissionDeniedError):
        await token_service.get_change_history(
            data, token=token.key, username=request.username
        )

    # Now request a service token with minimal data instead.
    request = AdminTokenRequest(
        username="service", token_type=TokenType.service
    )
    async with factory.session.begin():
        token = await token_service.create_token_from_admin_request(
            request, admin_data, ip_address="127.0.0.1"
        )
    service_data = await token_service.get_data(token)
    assert service_data and service_data == TokenData(
        token=token, created=service_data.created, **request.dict()
    )
    assert_is_now(service_data.created)

    async with factory.session.begin():
        history = await token_service.get_change_history(
            admin_data, token=token.key, username=request.username
        )
    assert history.entries == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=request.username,
            token_type=TokenType.service,
            scopes=[],
            expires=None,
            actor=admin_data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_time=service_data.created,
        )
    ]


@pytest.mark.asyncio
async def test_list(factory: ComponentFactory) -> None:
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info, scopes=["user:token"], ip_address="127.0.0.1"
        )
    data = await token_service.get_data(session_token)
    assert data
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            data,
            data.username,
            token_name="some-token",
            scopes=[],
            ip_address="127.0.0.1",
        )
        other_user_info = TokenUserInfo(
            username="other", name="Other Person", uid=1313
        )
        other_session_token = await token_service.create_session_token(
            other_user_info, scopes=["admin:token"], ip_address="1.1.1.1"
        )
    admin_data = await token_service.get_data(other_session_token)
    assert admin_data

    async with factory.session.begin():
        session_info = await token_service.get_token_info_unchecked(
            session_token.key
        )
        assert session_info
        user_token_info = await token_service.get_token_info_unchecked(
            user_token.key
        )
        assert user_token_info
        other_session_info = await token_service.get_token_info_unchecked(
            other_session_token.key
        )
        assert other_session_info
        assert await token_service.list_tokens(data, "example") == sorted(
            sorted((session_info, user_token_info), key=lambda t: t.token),
            key=lambda t: t.created,
            reverse=True,
        )
        assert await token_service.list_tokens(admin_data) == sorted(
            sorted(
                (session_info, other_session_info, user_token_info),
                key=lambda t: t.token,
            ),
            key=lambda t: t.created,
            reverse=True,
        )

    # Regular users can't retrieve all tokens.
    with pytest.raises(PermissionDeniedError):
        await token_service.list_tokens(data)


@pytest.mark.asyncio
async def test_modify(factory: ComponentFactory) -> None:
    user_info = TokenUserInfo(
        username="example", name="Example Person", uid=4137
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "user:token"],
            ip_address="127.0.0.1",
        )
    data = await token_service.get_data(session_token)
    assert data
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            data,
            data.username,
            token_name="some-token",
            scopes=[],
            ip_address="127.0.0.1",
        )

    expires = current_datetime() + timedelta(days=50)
    async with factory.session.begin():
        await token_service.modify_token(
            user_token.key,
            data,
            token_name="happy token",
            ip_address="127.0.0.1",
        )
        await token_service.modify_token(
            user_token.key,
            data,
            scopes=["read:all"],
            expires=expires,
            ip_address="192.168.0.4",
        )
        info = await token_service.get_token_info_unchecked(user_token.key)
    assert info and info == TokenInfo(
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
    async with factory.session.begin():
        await token_service.modify_token(
            user_token.key,
            data,
            expires=None,
            no_expire=True,
            ip_address="127.0.4.5",
        )

    async with factory.session.begin():
        history = await token_service.get_change_history(
            data, token=user_token.key, username=data.username
        )
    assert history.entries == [
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="happy token",
            scopes=["read:all"],
            expires=None,
            actor=data.username,
            action=TokenChange.edit,
            old_expires=expires,
            ip_address="127.0.4.5",
            event_time=history.entries[0].event_time,
        ),
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="happy token",
            scopes=["read:all"],
            expires=expires,
            actor=data.username,
            action=TokenChange.edit,
            old_scopes=[],
            old_expires=None,
            ip_address="192.168.0.4",
            event_time=history.entries[1].event_time,
        ),
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="happy token",
            scopes=[],
            expires=None,
            actor=data.username,
            action=TokenChange.edit,
            old_token_name="some-token",
            ip_address="127.0.0.1",
            event_time=history.entries[2].event_time,
        ),
        TokenChangeHistoryEntry(
            token=user_token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="some-token",
            scopes=[],
            expires=None,
            actor=data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_time=info.created,
        ),
    ]


@pytest.mark.asyncio
async def test_delete(factory: ComponentFactory) -> None:
    data = await create_session_token(factory)
    token_service = factory.create_token_service()
    async with factory.session.begin():
        token = await token_service.create_user_token(
            data,
            data.username,
            token_name="some token",
            scopes=[],
            ip_address="127.0.0.1",
        )

    async with factory.session.begin():
        assert await token_service.delete_token(
            token.key, data, data.username, ip_address="127.0.0.1"
        )

    assert await token_service.get_data(token) is None
    async with factory.session.begin():
        assert await token_service.get_token_info_unchecked(token.key) is None
        assert await token_service.get_user_info(token) is None

    async with factory.session.begin():
        assert not await token_service.delete_token(
            token.key, data, data.username, ip_address="127.0.0.1"
        )

    async with factory.session.begin():
        history = await token_service.get_change_history(
            data, token=token.key, username=data.username
        )
    assert history.entries == [
        TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="some token",
            scopes=[],
            expires=None,
            actor=data.username,
            action=TokenChange.revoke,
            ip_address="127.0.0.1",
            event_time=history.entries[0].event_time,
        ),
        TokenChangeHistoryEntry(
            token=token.key,
            username=data.username,
            token_type=TokenType.user,
            token_name="some token",
            scopes=[],
            expires=None,
            actor=data.username,
            action=TokenChange.create,
            ip_address="127.0.0.1",
            event_time=history.entries[1].event_time,
        ),
    ]

    # Cannot delete someone else's token.
    async with factory.session.begin():
        token = await token_service.create_user_token(
            data,
            data.username,
            token_name="some token",
            scopes=[],
            ip_address="127.0.0.1",
        )
    other_data = await create_session_token(factory, username="other")
    async with factory.session.begin():
        with pytest.raises(PermissionDeniedError):
            await token_service.delete_token(
                token.key, other_data, data.username, ip_address="127.0.0.1"
            )

    # Admins can delete soemone else's token.
    admin_data = await create_session_token(
        factory, username="admin", scopes=["admin:token"]
    )
    assert await token_service.get_data(token)
    async with factory.session.begin():
        assert await token_service.delete_token(
            token.key, admin_data, data.username, ip_address="127.0.0.1"
        )
    assert await token_service.get_data(token) is None


@pytest.mark.asyncio
async def test_delete_cascade(factory: ComponentFactory) -> None:
    """Test that deleting a token cascades to child tokens."""
    token_service = factory.create_token_service()
    session_token_data = await create_session_token(
        factory, scopes=["admin:token", "read:all", "user:token"]
    )
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            session_token_data,
            session_token_data.username,
            token_name="user-token",
            scopes=["user:token"],
            ip_address="127.0.0.1",
        )
        user_token_data = await token_service.get_data(user_token)
        assert user_token_data
        admin_request = AdminTokenRequest(
            username="service",
            token_type=TokenType.service,
            scopes=["read:all", "user:token"],
            name="Some Service",
        )
        service_token = await token_service.create_token_from_admin_request(
            admin_request, session_token_data, ip_address="127.0.0.1"
        )
        service_token_data = await token_service.get_data(service_token)
        assert service_token_data

    # Build a tree of tokens hung off of the session token.
    async with factory.session.begin():
        notebook_token = await token_service.get_notebook_token(
            session_token_data, ip_address="127.0.0.1"
        )
        notebook_token_data = await token_service.get_data(notebook_token)
        assert notebook_token_data
        session_children = [
            notebook_token,
            await token_service.get_internal_token(
                session_token_data,
                "service-a",
                scopes=[],
                ip_address="127.0.0.1",
            ),
            await token_service.get_internal_token(
                notebook_token_data,
                "service-b",
                scopes=[],
                ip_address="127.0.0.1",
            ),
            await token_service.get_internal_token(
                notebook_token_data,
                "service-a",
                scopes=["read:all"],
                ip_address="127.0.0.1",
            ),
        ]
        internal_token_data = await token_service.get_data(
            session_children[-1]
        )
        assert internal_token_data
        session_children.append(
            await token_service.get_internal_token(
                internal_token_data,
                "service-b",
                scopes=["read:all"],
                ip_address="127.0.0.1",
            )
        )

    # Shorter trees of tokens from the user and service tokens.
    async with factory.session.begin():
        user_children = [
            await token_service.get_internal_token(
                user_token_data, "service-c", scopes=[], ip_address="127.0.0.1"
            ),
            await token_service.get_notebook_token(
                user_token_data, ip_address="127.0.0.1"
            ),
        ]
        service_children = [
            await token_service.get_internal_token(
                service_token_data,
                "service-a",
                scopes=[],
                ip_address="127.0.0.1",
            )
        ]

    # Deleting the session token should invalidate all of its children.
    async with factory.session.begin():
        assert await token_service.delete_token(
            session_token_data.token.key,
            session_token_data,
            session_token_data.username,
            ip_address="127.0.0.1",
        )
    for token in session_children:
        assert await token_service.get_data(token) is None

    # But the user and service token created by this token should not be
    # deleted.
    assert await token_service.get_data(user_token_data.token)
    assert await token_service.get_data(service_token_data.token)

    # Deleting those tokens should cascade to their children.
    async with factory.session.begin():
        assert await token_service.delete_token(
            user_token_data.token.key,
            user_token_data,
            user_token_data.username,
            ip_address="127.0.0.1",
        )
    for token in user_children:
        assert await token_service.get_data(token) is None
    async with factory.session.begin():
        assert await token_service.delete_token(
            service_token_data.token.key,
            service_token_data,
            service_token_data.username,
            ip_address="127.0.0.1",
        )
    for token in service_children:
        assert await token_service.get_data(token) is None


@pytest.mark.asyncio
async def test_modify_expires(
    config: Config, factory: ComponentFactory
) -> None:
    """Test that expiration changes cascade to subtokens."""
    token_service = factory.create_token_service()
    session_token_data = await create_session_token(
        factory, scopes=["user:token"]
    )

    # Create a user token with no expiration and some additional tokens
    # chained off of it.
    async with factory.session.begin():
        user_token = await token_service.create_user_token(
            session_token_data,
            session_token_data.username,
            token_name="user-token",
            scopes=["user:token"],
            ip_address="127.0.0.1",
        )
        user_token_data = await token_service.get_data(user_token)
        assert user_token_data
        notebook_token = await token_service.get_notebook_token(
            user_token_data, ip_address="127.0.0.1"
        )
        notebook_token_data = await token_service.get_data(notebook_token)
        assert notebook_token_data
        internal_token = await token_service.get_internal_token(
            user_token_data, "service-a", scopes=[], ip_address="127.0.0.1"
        )
        internal_token_data = await token_service.get_data(internal_token)
        assert internal_token_data
        nested_token = await token_service.get_internal_token(
            notebook_token_data, "service-b", scopes=[], ip_address="127.0.0.1"
        )
        nested_token_data = await token_service.get_data(nested_token)
        assert nested_token_data

    # Check the expiration of all of those tokens matches the default
    # expiration for generated tokens.
    delta = timedelta(minutes=config.issuer.exp_minutes)
    assert notebook_token_data.expires == notebook_token_data.created + delta
    assert internal_token_data.expires == internal_token_data.created + delta
    assert nested_token_data.expires == notebook_token_data.expires

    # Check that Redis also has an appropriate TTL.
    redis = await redis_dependency()
    ttl = delta.total_seconds()
    for token in (notebook_token, internal_token, nested_token):
        assert ttl - 5 <= await redis.ttl(f"token:{token.key}") <= ttl

    # Change the expiration of the user token.
    new_delta = timedelta(minutes=config.issuer.exp_minutes / 2)
    new_expires = user_token_data.created + new_delta
    async with factory.session.begin():
        await token_service.modify_token(
            user_token.key,
            user_token_data,
            expires=new_expires,
            ip_address="127.0.0.1",
        )

    # Check that all of the tokens have been updated.
    notebook_token_data = await token_service.get_data(notebook_token)
    assert notebook_token_data
    internal_token_data = await token_service.get_data(internal_token)
    assert internal_token_data
    nested_token_data = await token_service.get_data(nested_token)
    assert nested_token_data
    assert notebook_token_data.expires == new_expires
    assert internal_token_data.expires == new_expires
    assert nested_token_data.expires == new_expires

    # Check that the Redis TTL has also been updated.
    ttl = new_delta.total_seconds()
    for token in (notebook_token, internal_token, nested_token):
        assert ttl - 5 <= await redis.ttl(f"token:{token.key}") <= ttl


@pytest.mark.asyncio
async def test_invalid(config: Config, factory: ComponentFactory) -> None:
    redis = await redis_dependency()
    token_service = factory.create_token_service()
    expires = int(timedelta(days=1).total_seconds())

    # No such key.
    token = Token()
    assert await token_service.get_data(token) is None

    # Invalid encrypted blob.
    await redis.set(f"token:{token.key}", "foo", ex=expires)
    assert await token_service.get_data(token) is None

    # Malformed session.
    fernet = Fernet(config.session_secret.encode())
    raw_data = fernet.encrypt(b"malformed json")
    await redis.set(f"token:{token.key}", raw_data, ex=expires)
    assert await token_service.get_data(token) is None

    # Mismatched token.
    data = TokenData(
        token=Token(),
        username="example",
        token_type=TokenType.session,
        scopes=[],
        created=int(current_datetime().timestamp()),
        name="Some User",
        uid=12345,
    )
    session = fernet.encrypt(data.json().encode())
    await redis.set(f"token:{token.key}", session, ex=expires)
    assert await token_service.get_data(token) is None

    # Missing required fields.
    json_data = {
        "token": {
            "key": token.key,
            "secret": token.secret,
        },
        "token_type": "session",
        "scopes": [],
        "created": int(current_datetime().timestamp()),
        "name": "Some User",
    }
    raw_data = fernet.encrypt(json.dumps(json_data).encode())
    await redis.set(f"token:{token.key}", raw_data, ex=expires)
    assert await token_service.get_data(token) is None

    # Fix the session store and confirm we can retrieve the manually-stored
    # session.
    json_data["username"] = "example"
    raw_data = fernet.encrypt(json.dumps(json_data).encode())
    await redis.set(f"token:{token.key}", raw_data, ex=expires)
    new_data = await token_service.get_data(token)
    assert new_data == TokenData.parse_obj(json_data)


@pytest.mark.asyncio
async def test_invalid_username(factory: ComponentFactory) -> None:
    user_info = TokenUserInfo(
        username="ex-am-pl-e",
        name="Example Person",
        uid=4137,
        groups=[TokenGroup(name="foo", id=1000)],
    )
    token_service = factory.create_token_service()
    async with factory.session.begin():
        session_token = await token_service.create_session_token(
            user_info,
            scopes=["read:all", "admin:token"],
            ip_address="127.0.0.1",
        )
    data = await token_service.get_data(session_token)
    assert data

    # Cannot create any type of token with an invalid name.
    for user in (
        "<bootstrap>",
        "<internal>",
        "in+valid",
        " invalid",
        "invalid ",
        "in/valid",
        "in@valid",
        "-invalid",
        "invalid-",
        "in--valid",
    ):
        user_info.username = user
        with pytest.raises(PermissionDeniedError):
            await token_service.create_session_token(
                user_info, scopes=[], ip_address="127.0.0.1"
            )
        data.username = user
        with pytest.raises(PermissionDeniedError):
            await token_service.create_user_token(
                data, user, token_name="n", scopes=[], ip_address="127.0.0.1"
            )
        with pytest.raises(PermissionDeniedError):
            await token_service.get_notebook_token(
                data, ip_address="127.0.0.1"
            )
        with pytest.raises(PermissionDeniedError):
            await token_service.get_internal_token(
                data, service="s", scopes=[], ip_address="127.0.0.1"
            )
        with pytest.raises(ValidationError):
            AdminTokenRequest(username=user, token_type=TokenType.service)
        request = AdminTokenRequest(
            username="valid", token_type=TokenType.service
        )
        request.username = user
        with pytest.raises(PermissionDeniedError):
            await token_service.create_token_from_admin_request(
                request, data, ip_address="127.0.0.1"
            )
