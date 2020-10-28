"""Test fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from sqlalchemy import create_engine

from gafaelfawr.schema import initialize_schema
from tests.support.constants import TEST_HOSTNAME
from tests.support.selenium import run_app, selenium_driver
from tests.support.settings import build_settings
from tests.support.setup import SetupTest

if TYPE_CHECKING:
    from pathlib import Path
    from typing import AsyncIterator, Iterable, Iterator, List

    from pytest_httpx import HTTPXMock
    from seleniumwire import webdriver


@pytest.fixture(scope="session")
def driver() -> Iterator[webdriver.Chrome]:
    """Create a driver for Selenium testing.

    Returns
    -------
    driver : `selenium.webdriver.Chrome`
        The web driver to use in Selenium tests.
    """
    driver = selenium_driver()
    try:
        yield driver
    finally:
        driver.quit()


@pytest.fixture
def non_mocked_hosts() -> List[str]:
    """Disable pytest-httpx mocking for the test application."""
    return [TEST_HOSTNAME, "localhost"]


@pytest.fixture
def selenium_server_url(tmp_path: Path, sqlite_db_url: str) -> Iterable[str]:
    """Start a server for Selenium tests.

    The server will be automatically stopped at the end of the test.

    Returns
    -------
    server_url : `str`
        The URL to use to contact that server.
    """
    settings_path = build_settings(
        tmp_path, "selenium", database_url=sqlite_db_url
    )
    with run_app(tmp_path, settings_path) as server_url:
        yield server_url


@pytest.fixture
async def setup(
    tmp_path: Path, httpx_mock: HTTPXMock, sqlite_db_url: str
) -> AsyncIterator[SetupTest]:
    """Create a test setup object.

    This encapsulates a lot of the configuration and machinery of setting up
    tests, mocking responses, and doing repetitive checks.  This fixture must
    be referenced even if not used to set up the application properly for
    testing.

    Returns
    -------
    setup : `tests.support.setup.SetupTest`
        The setup object.
    """
    async with SetupTest.create(tmp_path, sqlite_db_url, httpx_mock) as setup:
        yield setup


@pytest.fixture
def sqlite_db_url(tmp_path: Path) -> str:
    """Create a SQLite database and return its URL."""
    database_url = "sqlite:///" + str(tmp_path / "gafaelfawr.sqlite")
    engine = create_engine(database_url)
    initialize_schema(engine)
    return database_url
