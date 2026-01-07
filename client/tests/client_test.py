"""Tests for the Gafaelfawr client."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import respx
from rubin.repertoire import register_mock_discovery

from rubin.gafaelfawr import (
    GafaelfawrClient,
    GafaelfawrDiscoveryError,
    GafaelfawrGroup,
    GafaelfawrNotFoundError,
    GafaelfawrUserInfo,
    GafaelfawrWebError,
    MockGafaelfawr,
    MockGafaelfawrAction,
)

from .support.data import read_test_user_info


@pytest.mark.asyncio
async def test_create_token(mock_gafaelfawr: MockGafaelfawr) -> None:
    token = mock_gafaelfawr.create_token("admin", scopes=["admin:token"])
    client = GafaelfawrClient()

    # Create a minimal token with just a username.
    service_token = await client.create_service_token(
        token, "bot-service", scopes=[]
    )
    userinfo = await client.get_user_info(service_token)
    assert userinfo == GafaelfawrUserInfo(username="bot-service")

    # This token has no scopes so should not be able to retrieve user
    # information by username.
    with pytest.raises(GafaelfawrWebError) as exc_info:
        await client.get_user_info(service_token, "bot-service")
    assert exc_info.value.status == 403

    # Create a token with all of the fields set.
    service_token = await client.create_service_token(
        token,
        "bot-service",
        scopes=["admin:userinfo"],
        expires=datetime.now(tz=UTC) + timedelta(days=1),
        name="Some bot user",
        uid=4000,
        gid=4001,
        groups=[GafaelfawrGroup(name="group", id=5000)],
    )
    expected = GafaelfawrUserInfo(
        username="bot-service",
        name="Some bot user",
        uid=4000,
        gid=4001,
        groups=[GafaelfawrGroup(name="group", id=5000)],
    )
    assert await client.get_user_info(service_token) == expected

    # This token has admin:userinfo, so can get user information by username.
    assert await client.get_user_info(service_token, "bot-service") == expected


@pytest.mark.asyncio
async def test_missing_discovery(
    monkeypatch: pytest.MonkeyPatch, respx_mock: respx.Router
) -> None:
    monkeypatch.setenv("REPERTOIRE_BASE_URL", "https://example.com/repertoire")
    path = Path(__file__).parent / "data" / "empty.json"
    register_mock_discovery(respx_mock, path)
    client = GafaelfawrClient()

    # If the Gafaelfawr service (v1) is not included in the discovery
    # information, any client call should raise GafaelfawrDiscoveryError.
    with pytest.raises(GafaelfawrDiscoveryError):
        await client.get_user_info("some-token")


@pytest.mark.asyncio
async def test_userinfo_by_username(mock_gafaelfawr: MockGafaelfawr) -> None:
    token = mock_gafaelfawr.create_token("admin", scopes=["admin:userinfo"])
    user_info = read_test_user_info("someuser")
    client = GafaelfawrClient()

    # If no data is available, should raise GafaelfawrNotFoundError.
    with pytest.raises(GafaelfawrNotFoundError):
        await client.get_user_info(token, "someuser")

    # HTTP errors should raise GafaelfawrWebError.
    mock_gafaelfawr.fail_on("someuser", MockGafaelfawrAction.USER_INFO)
    with pytest.raises(GafaelfawrWebError):
        await client.get_user_info(token, "someuser")

    # Register some user information and try again.
    mock_gafaelfawr.fail_on("someuser", [])
    mock_gafaelfawr.set_user_info("someuser", user_info)
    assert await client.get_user_info(token, "someuser") == user_info


@pytest.mark.asyncio
async def test_cache_by_username(mock_gafaelfawr: MockGafaelfawr) -> None:
    token = mock_gafaelfawr.create_token("admin", scopes=["admin:userinfo"])
    user_info = read_test_user_info("someuser")
    empty_user_info = GafaelfawrUserInfo(username="someuser")
    client = GafaelfawrClient()

    # Register the empty object at first.
    mock_gafaelfawr.set_user_info("someuser", empty_user_info)
    assert await client.get_user_info(token, "someuser") == empty_user_info

    # Changing the underlying user information shouldn't change the result
    # since it is still cached.
    mock_gafaelfawr.set_user_info("someuser", user_info)
    assert await client.get_user_info(token, "someuser") == empty_user_info

    # Clearing the cache should result in the new data.
    await client.clear_cache()
    assert await client.get_user_info(token, "someuser") == user_info


@pytest.mark.asyncio
async def test_userinfo_by_token(mock_gafaelfawr: MockGafaelfawr) -> None:
    token = mock_gafaelfawr.create_token("someuser")
    user_info = read_test_user_info("someuser")
    client = GafaelfawrClient()

    # If no data is available, should raise GafaelfawrNotFoundError.
    with pytest.raises(GafaelfawrNotFoundError):
        await client.get_user_info(token)

    # HTTP errors should raise GafaelfawrWebError.
    mock_gafaelfawr.fail_on("someuser", MockGafaelfawrAction.USER_INFO)
    with pytest.raises(GafaelfawrWebError):
        await client.get_user_info(token)

    # Register some user information and try again.
    mock_gafaelfawr.fail_on("someuser", [])
    mock_gafaelfawr.set_user_info("someuser", user_info)
    assert await client.get_user_info(token) == user_info


@pytest.mark.asyncio
async def test_cache_by_token(mock_gafaelfawr: MockGafaelfawr) -> None:
    token = mock_gafaelfawr.create_token("someuser")
    user_info = read_test_user_info("someuser")
    empty_user_info = GafaelfawrUserInfo(username="someuser")
    client = GafaelfawrClient()

    # Register the empty object at first.
    mock_gafaelfawr.set_user_info("someuser", empty_user_info)
    assert await client.get_user_info(token) == empty_user_info

    # Changing the underlying user information shouldn't change the result
    # since it is still cached.
    mock_gafaelfawr.set_user_info("someuser", user_info)
    assert await client.get_user_info(token) == empty_user_info

    # Clearing the cache should result in the new data.
    await client.clear_cache()
    assert await client.get_user_info(token) == user_info
