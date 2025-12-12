"""Tests for the Gafaelfawr mock.

Most of the functionality of the mock is tested by the regular client tests,
but test a few additional behaviors that the client tests didn't need or that
are specific to the mock.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import respx
from rubin.repertoire import register_mock_discovery

from rubin.gafaelfawr import (
    GafaelfawrClient,
    GafaelfawrUserInfo,
    GafaelfawrWebError,
    MockGafaelfawr,
    MockGafaelfawrAction,
    register_mock_gafaelfawr,
)

from .support.data import read_test_user_info


@pytest.mark.asyncio
async def test_bad_token(mock_gafaelfawr: MockGafaelfawr) -> None:
    client = GafaelfawrClient()
    mock_gafaelfawr.set_user_info("someuser", read_test_user_info("someuser"))

    # Making a request with an invalid token should return a 403 error.
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.get_user_info("some-token", "someuser")
    assert exc_info.value.status == 403


@pytest.mark.asyncio
async def test_create_token_expires(mock_gafaelfawr: MockGafaelfawr) -> None:
    client = GafaelfawrClient()
    mock_gafaelfawr.set_user_info("someuser", read_test_user_info("someuser"))

    # Creating a token that is already expired should be reflected in the
    # token information and cause the token to be rejected in later calls.
    token = mock_gafaelfawr.create_token(
        "someuser", expires=datetime.now(tz=UTC) - timedelta(seconds=2)
    )
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.get_user_info(token)
    assert exc_info.value.status == 401


@pytest.mark.asyncio
async def test_fail_on(mock_gafaelfawr: MockGafaelfawr) -> None:
    client = GafaelfawrClient()
    token = mock_gafaelfawr.create_token("someuser")
    mock_gafaelfawr.set_user_info("someuser", read_test_user_info("someuser"))
    admin_token = mock_gafaelfawr.create_token(
        "admin", scopes=["admin:userinfo", "admin:token"]
    )
    admin_userinfo = GafaelfawrUserInfo(username="admin")
    mock_gafaelfawr.set_user_info("admin", admin_userinfo)

    # Setting failure for user info for a user should block both ways of
    # retrieving the user information.
    mock_gafaelfawr.fail_on("someuser", MockGafaelfawrAction.USER_INFO)
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.get_user_info(token)
    assert exc_info.value.status == 500
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.get_user_info(admin_token, "someuser")
    assert exc_info.value.status == 500

    # Getting the user information for the admin token works.
    assert await client.get_user_info(admin_token) == admin_userinfo

    # Check failure for creating a token.
    mock_gafaelfawr.fail_on("admin", MockGafaelfawrAction.CREATE_TOKEN)
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.create_service_token(admin_token, "bot-user", scopes=[])


@pytest.mark.asyncio
async def test_missing_discovery(
    monkeypatch: pytest.MonkeyPatch, respx_mock: respx.Router
) -> None:
    monkeypatch.setenv("REPERTOIRE_BASE_URL", "https://example.com/repertoire")
    path = Path(__file__).parent / "data" / "empty.json"
    register_mock_discovery(respx_mock, path)

    # If the Gafaelfawr service (v1) is not included in the discovery
    # information, register_mock_gafaelfawr should assert.
    with pytest.raises(AssertionError):
        await register_mock_gafaelfawr(respx_mock)


@pytest.mark.asyncio
async def test_required_scopes(mock_gafaelfawr: MockGafaelfawr) -> None:
    client = GafaelfawrClient()
    mock_gafaelfawr.set_user_info("someuser", read_test_user_info("someuser"))

    # A token without admin:userinfo should not be able to access the user
    # route used by get_user_info with an explicit username.
    token = mock_gafaelfawr.create_token("otheruser")
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.get_user_info(token, "someuser")
    assert exc_info.value.status == 403

    # A token without admin:token should not be able to create a token.
    token = mock_gafaelfawr.create_token("admin", scopes=["admin:userinfo"])
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.create_service_token(token, "bot-user", scopes=[])
    assert exc_info.value.status == 403


@pytest.mark.asyncio
async def test_service_token_expiration(
    mock_gafaelfawr: MockGafaelfawr,
) -> None:
    token = mock_gafaelfawr.create_token("admin", scopes=["admin:token"])
    client = GafaelfawrClient()

    # The expiration of a service token should be checked in later mock calls,
    # such as getting user information for the token.
    service_token = await client.create_service_token(
        token,
        "bot-user",
        expires=datetime.now(tz=UTC) - timedelta(seconds=2),
        scopes=[],
    )
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.get_user_info(service_token)
    assert exc_info.value.status == 401


@pytest.mark.asyncio
async def test_service_token_username(mock_gafaelfawr: MockGafaelfawr) -> None:
    token = mock_gafaelfawr.create_token("admin", scopes=["admin:token"])
    client = GafaelfawrClient()

    # Service token usernames must begin with "bot-".
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.create_service_token(token, "user", scopes=[])
    assert exc_info.value.status == 422
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.create_service_token(token, "botuser", scopes=[])
    assert exc_info.value.status == 422
