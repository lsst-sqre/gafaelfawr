"""Tests for the Gafaelfawr client."""

from __future__ import annotations

from pathlib import Path

import pytest
import respx
from rubin.repertoire import register_mock_discovery

from rubin.gafaelfawr import (
    GafaelfawrClient,
    GafaelfawrDiscoveryError,
    GafaelfawrNotFoundError,
    GafaelfawrUserInfo,
    GafaelfawrWebError,
    MockGafaelfawr,
    MockGafaelfawrAction,
)

from .support.data import read_test_user_info


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
