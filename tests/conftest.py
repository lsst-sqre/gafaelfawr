"""Test fixtures."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from aioresponses import aioresponses
from httpx import AsyncClient

from gafaelfawr.main import app
from tests.setup import SetupTest
from tests.support.app import build_config
from tests.support.constants import TEST_HOSTNAME
from tests.support.selenium import run_app, selenium_driver

if TYPE_CHECKING:
    from asyncio import AbstractEventLoop
    from pathlib import Path
    from typing import AsyncIterator, Iterable, Iterator

    from seleniumwire import webdriver


@pytest.fixture
async def client(loop: AbstractEventLoop) -> AsyncIterator[AsyncClient]:
    """Provide an httpx client configured to talk to the test app.

    Returns
    -------
    client : `httpx.AsyncClient`
        Client wrapping the Gafaelfawr app.  The base URL will use
        :py:const:`tests.support.constants.TEST_HOSTNAME`.
    """
    base_url = f"https://{TEST_HOSTNAME}"
    async with AsyncClient(app=app, base_url=base_url) as client:
        yield client


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
def responses() -> Iterable[aioresponses]:
    """Create an aioresponses context manager.

    This can be used to mock responses to calls in an `aiohttp.ClientSession`.

    Returns
    -------
    mock : `aioresponses.aioresponses`
        The mock object with which URLs and callbacks can be registered.
    """
    with aioresponses(passthrough=["http://127.0.0.1"]) as mock:
        yield mock


@pytest.fixture
def selenium_server_url(tmp_path: Path) -> Iterable[str]:
    """Start a server for Selenium tests.

    The server will be automatically stopped at the end of the test.

    Returns
    -------
    server_url : `str`
        The URL to use to contact that server.
    """
    config_path = build_config(tmp_path, environment="selenium")
    with run_app(tmp_path, config_path) as url:
        yield url


@pytest.fixture
async def setup(
    tmp_path: Path, responses: aioresponses, loop: AbstractEventLoop
) -> AsyncIterator[SetupTest]:
    """Create a test setup object.

    This encapsulates a lot of the configuration and machinery of setting up
    tests, mocking responses, and doing repetitive checks.  This fixture must
    be referenced even if not used to set up the application properly for
    testing.

    Returns
    -------
    setup : `tests.setup.SetupTest`
        The setup object.
    """
    test_setup = await SetupTest.create(tmp_path, responses)
    try:
        yield test_setup
    finally:
        await test_setup.close()
