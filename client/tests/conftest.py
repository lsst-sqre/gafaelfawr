"""Test fixtures for Gafaelfawr client testing."""

from pathlib import Path

import pytest
import pytest_asyncio
import respx
from rubin.repertoire import Discovery, register_mock_discovery

from rubin.gafaelfawr import MockGafaelfawr, register_mock_gafaelfawr


@pytest.fixture
def mock_discovery(
    respx_mock: respx.Router, monkeypatch: pytest.MonkeyPatch
) -> Discovery:
    monkeypatch.setenv("REPERTOIRE_BASE_URL", "https://example.com/repertoire")
    path = Path(__file__).parent / "data" / "discovery.json"
    return register_mock_discovery(respx_mock, path)


@pytest_asyncio.fixture
async def mock_gafaelfawr(
    mock_discovery: Discovery, respx_mock: respx.Router
) -> MockGafaelfawr:
    return await register_mock_gafaelfawr(respx_mock)
