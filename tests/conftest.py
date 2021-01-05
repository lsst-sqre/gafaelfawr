"""Test fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from gafaelfawr.dependencies.config import config_dependency
from tests.support.constants import TEST_HOSTNAME
from tests.support.selenium import run_app, selenium_driver
from tests.support.settings import build_settings
from tests.support.setup import SetupTest

if TYPE_CHECKING:
    from pathlib import Path
    from typing import AsyncIterator, Iterable, Iterator, List

    from pytest_httpx import HTTPXMock
    from seleniumwire import webdriver

    from tests.support.selenium import SeleniumConfig


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
def selenium_config(tmp_path: Path) -> Iterable[SeleniumConfig]:
    """Start a server for Selenium tests.

    The server will be automatically stopped at the end of the test.

    Returns
    -------
    config : `tests.support.selenium.SeleniumConfig`
        Configuration information for the server.
    """
    database_url = "sqlite:///" + str(tmp_path / "gafaelfawr.sqlite")
    settings_path = build_settings(
        tmp_path, "selenium", database_url=database_url
    )
    config_dependency.set_settings_path(str(settings_path))
    with run_app(tmp_path, settings_path) as config:
        yield config


@pytest.fixture
async def setup(
    tmp_path: Path, httpx_mock: HTTPXMock
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
    async with SetupTest.create(tmp_path, httpx_mock) as setup:
        yield setup
