"""Test fixtures."""

from __future__ import annotations

from pathlib import Path
from typing import AsyncIterator, Iterator
from unittest.mock import patch
from urllib.parse import urljoin

import bonsai
import pytest
import pytest_asyncio
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import AsyncClient
from safir.testing.kubernetes import MockKubernetesApi, patch_kubernetes
from seleniumwire import webdriver

from gafaelfawr import main
from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.database import initialize_database
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.models.state import State
from gafaelfawr.models.token import TokenType

from .pages.tokens import TokensPage
from .support.constants import TEST_HOSTNAME
from .support.ldap import MockLDAP
from .support.selenium import SeleniumConfig, run_app, selenium_driver
from .support.settings import build_settings


@pytest_asyncio.fixture
async def app(empty_database: None) -> AsyncIterator[FastAPI]:
    """Return a configured test application.

    Wraps the application in a lifespan manager so that startup and shutdown
    events are sent during test execution.
    """
    async with LifespanManager(main.app):
        yield main.app


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """Return an ``httpx.AsyncClient`` configured to talk to the test app."""
    base_url = f"https://{TEST_HOSTNAME}"
    async with AsyncClient(app=app, base_url=base_url) as client:
        yield client


@pytest.fixture
def config(tmp_path: Path) -> Config:
    """Set up and return the default test configuration.

    Notes
    -----
    This fixture must not be async so that it can be used by the cli tests,
    which must not be async because the Click support starts its own asyncio
    loop.
    """
    settings_path = build_settings(tmp_path, "github")
    config_dependency.set_settings_path(str(settings_path))
    assert config_dependency._config
    return config_dependency._config


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


@pytest_asyncio.fixture
async def empty_database(config: Config) -> None:
    """Initialize the database for a new test.

    This exists as a fixture so that multiple other fixtures can depend on it
    and avoid any duplication of work if, say, we need both a configured
    FastAPI app and a standalone factory.

    Notes
    -----
    This always uses a settings file configured for GitHub authentication for
    the database initialization and initial app configuration.  Use
    `tests.support.settings.configure` after the test has started to change
    this if needed for a given test, or avoid this fixture and any that depend
    on it if control over the configuration prior to database initialization
    is required.
    """
    await initialize_database(config, reset=True)


@pytest_asyncio.fixture
async def factory(empty_database: None) -> AsyncIterator[ComponentFactory]:
    """Return a component factory.

    Note that this creates a separate SQLAlchemy AsyncSession from any that
    may be created by the FastAPI app.
    """
    async with ComponentFactory.standalone() as factory:
        yield factory


@pytest.fixture
def mock_kubernetes() -> Iterator[MockKubernetesApi]:
    """Replace the Kubernetes API with a mock class.

    Returns
    -------
    mock_kubernetes : `safir.testing.kubernetes.MockKubernetesApi`
        The mock Kubernetes API object.
    """
    yield from patch_kubernetes()


@pytest_asyncio.fixture
async def mock_ldap(tmp_path: Path, config: Config) -> AsyncIterator[MockLDAP]:
    """Replace the bonsai LDAP API with a mock class.

    Returns
    -------
    mock_ldap : `tests.support.ldap.MockLDAP`
        The mock LDAP API object.
    """
    settings_path = build_settings(tmp_path, "oidc-ldap")
    config_dependency.set_settings_path(str(settings_path))
    config = await config_dependency()
    assert config.ldap
    ldap = MockLDAP(config.ldap)
    with patch.object(bonsai, "LDAPClient") as mock:
        mock.return_value = ldap
        yield ldap


@pytest_asyncio.fixture
async def selenium_config(
    tmp_path: Path, driver: webdriver.Chrome, empty_database: None
) -> AsyncIterator[SeleniumConfig]:
    """Start a server for Selenium tests.

    The server will be automatically stopped at the end of the test.  The
    Selenium web driver will be automatically configured with a valid
    authentication token in a cookie.

    Returns
    -------
    config : `tests.support.selenium.SeleniumConfig`
        Configuration information for the server.
    """
    settings_path = build_settings(tmp_path, "selenium")
    config_dependency.set_settings_path(str(settings_path))
    async with run_app(tmp_path, settings_path) as config:
        cookie = await State(token=config.token).as_cookie()
        driver.header_overrides = {"Cookie": f"{COOKIE_NAME}={cookie}"}

        # The synthetic cookie doesn't have a CSRF token, so we want to
        # replace it with a real cookie.  Do this by visiting the top-level
        # page of the UI and waiting for the token list to appear, which will
        # trigger fleshing out the state, and then dropping the header
        # override for subsequent calls so that the cookie set in the browser
        # will be used.
        driver.get(urljoin(config.url, "/auth/tokens/"))
        tokens_page = TokensPage(driver)
        tokens_page.get_tokens(TokenType.session)
        del driver.header_overrides

        yield config
