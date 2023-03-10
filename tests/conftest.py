"""Test fixtures."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from urllib.parse import urljoin

import pytest
import pytest_asyncio
import respx
import structlog
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import AsyncClient
from safir.database import create_database_engine, initialize_database
from safir.dependencies.db_session import db_session_dependency
from safir.testing.slack import MockSlack, mock_slack_webhook
from seleniumwire import webdriver
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.factory import Factory
from gafaelfawr.main import create_app
from gafaelfawr.models.state import State
from gafaelfawr.models.token import TokenType
from gafaelfawr.schema import Base

from .pages.tokens import TokensPage
from .support.config import build_config, configure
from .support.constants import TEST_DATABASE_URL, TEST_HOSTNAME
from .support.firestore import MockFirestore, patch_firestore
from .support.ldap import MockLDAP, patch_ldap
from .support.selenium import SeleniumConfig, run_app, selenium_driver


@pytest_asyncio.fixture
async def app(
    engine: AsyncEngine, empty_database: None, mock_slack: MockSlack | None
) -> AsyncIterator[FastAPI]:
    """Return a configured test application.

    Wraps the application in a lifespan manager so that startup and shutdown
    events are sent during test execution.
    """
    db_session_dependency.override_engine(engine)
    app = create_app()
    async with LifespanManager(app):
        yield app


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
    return configure(tmp_path, "github")


@pytest.fixture(scope="session")
def driver() -> Iterator[webdriver.Chrome]:
    """Create a driver for Selenium testing."""
    driver = selenium_driver()
    try:
        yield driver
    finally:
        driver.quit()


@pytest_asyncio.fixture
async def empty_database(
    initialize_empty_database: None, engine: AsyncEngine, config: Config
) -> None:
    """Empty the database before a test.

    The tables are reset with ``TRUNCATE`` rather than dropping and recreating
    them in the hope that this will make database initialization faster.

    Notes
    -----

    This always uses a configuration file configured for GitHub authentication
    for the database initialization and initial app configuration.  Use
    `tests.support.config.configure` after the test has started to change this
    if needed for a given test, or avoid this fixture and any that depend on
    it if control over the configuration prior to database initialization is
    required.
    """
    tables = (t.name for t in Base.metadata.sorted_tables)
    async with Factory.standalone(config, engine) as factory:
        admin_service = factory.create_admin_service()
        async with factory.session.begin():
            stmt = text(f'TRUNCATE TABLE {", ".join(tables)}')
            await factory.session.execute(stmt)
            await admin_service.add_initial_admins(config.initial_admins)
        await factory._context.redis.flushdb()


@pytest.fixture(scope="session")
def engine() -> AsyncEngine:
    """Create a database engine for testing.

    Rather than allowing the `~gafaelfawr.factory.Factory` to create
    its own database engine, create a single engine at session scope.  This
    allows all the tests to share a single connection pool and not constantly
    open and close connections to the database, which in turn reduces the time
    it takes to run tests.
    """
    return create_database_engine(TEST_DATABASE_URL, None)


@pytest_asyncio.fixture
async def factory(
    empty_database: None, config: Config, engine: AsyncEngine
) -> AsyncIterator[Factory]:
    """Return a component factory.

    Note that this creates a separate SQLAlchemy async_scoped_session from any
    that may be created by the FastAPI app.
    """
    async with Factory.standalone(config, engine) as factory:
        yield factory


@pytest.fixture(scope="session")
def event_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """Increase the scope of the event loop to the test session.

    If this isn't done, an `~sqlalchemy.ext.asyncio.AsyncEngine` cannot be
    used from more than one test because they run in different loops, which in
    turn defeats connection pooling to speed up test execution.
    """
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def initialize_empty_database(engine: AsyncEngine) -> None:
    """Initialize the database for testing.

    This sets up the database schema for the tests.  The database is then
    reset between tests with the `empty_database` fixture.
    """
    logger = structlog.get_logger(__name__)
    await initialize_database(engine, logger, schema=Base.metadata, reset=True)


@pytest.fixture
def mock_firestore(tmp_path: Path) -> Iterator[MockFirestore]:
    """Configure Firestore UID/GID assignment and mock the Firestore API."""
    yield from patch_firestore()


@pytest.fixture
def mock_ldap() -> Iterator[MockLDAP]:
    """Replace the bonsai LDAP API with a mock class."""
    yield from patch_ldap()


@pytest.fixture
def mock_slack(config: Config, respx_mock: respx.Router) -> MockSlack | None:
    """Mock a Slack webhook."""
    if not config.slack_webhook:
        return None
    return mock_slack_webhook(config.slack_webhook, respx_mock)


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
    SeleniumConfig
        Configuration information for the server.
    """
    config_path = build_config(tmp_path, "selenium")
    config_dependency.set_config_path(config_path)
    async with run_app(tmp_path, config_path) as config:
        cookie = State(token=config.token).to_cookie()
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
