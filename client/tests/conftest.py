"""Test fixtures for Gafaelfawr client testing."""

from pathlib import Path

import pytest
import pytest_asyncio
import respx
from rubin.repertoire import Discovery, register_mock_discovery
from safir.testing.data import Data

from rubin.gafaelfawr import MockGafaelfawr, register_mock_gafaelfawr


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--update-test-data",
        action="store_true",
        default=False,
        help="Overwrite expected test output with current results",
    )


@pytest.fixture
def data(request: pytest.FixtureRequest) -> Data:
    update = request.config.getoption("--update-test-data")
    return Data(Path(__file__).parent / "data", update_test_data=update)


@pytest.fixture
def mock_discovery(
    data: Data, respx_mock: respx.Router, monkeypatch: pytest.MonkeyPatch
) -> Discovery:
    monkeypatch.setenv("REPERTOIRE_BASE_URL", "https://example.com/repertoire")
    return register_mock_discovery(respx_mock, data.path("discovery.json"))


@pytest_asyncio.fixture
async def mock_gafaelfawr(
    mock_discovery: Discovery, respx_mock: respx.Router
) -> MockGafaelfawr:
    return await register_mock_gafaelfawr(respx_mock)
