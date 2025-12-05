"""Tests for the Gafaelfawr mock.

Most of the functionality of the mock is tested by the regular client tests,
but test a few additional behaviors that the client tests didn't need or that
are specific to the mock.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import respx
from rubin.repertoire import register_mock_discovery

from rubin.gafaelfawr import (
    GafaelfawrClient,
    GafaelfawrWebError,
    MockGafaelfawr,
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
