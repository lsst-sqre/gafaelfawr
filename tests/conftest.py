"""Test fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from urllib.parse import urljoin

import pytest
import pytest_asyncio
import respx
import structlog
from alembic.config import Config as AlembicConfig
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from asgi_lifespan import LifespanManager
from fastapi import FastAPI
from httpx import AsyncClient
from safir.database import create_database_engine, initialize_database
from safir.dependencies.db_session import db_session_dependency
from safir.testing.slack import MockSlackWebhook, mock_slack_webhook
from seleniumwire import webdriver
from sqlalchemy import Connection, text
from sqlalchemy.exc import ProgrammingError
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
    engine: AsyncEngine,
    empty_database: None,
    mock_slack: MockSlackWebhook | None,
) -> AsyncIterator[FastAPI]:
    """Return a configured test application.

    Wraps the application in a lifespan manager so that startup and shutdown
    events are sent during test execution.
    """
    db_session_dependency.override_engine(engine)
    app = create_app(validate_schema=False)
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
async def empty_database(engine: AsyncEngine, config: Config) -> None:
    """Empty the database before a test.

    Notes
    -----
    This always uses a configuration file configured for GitHub authentication
    for the database initialization and initial app configuration.  Use
    `tests.support.config.configure` after the test has started to change this
    if needed for a given test, or avoid this fixture and any that depend on
    it if control over the configuration prior to database initialization is
    required.
    """
    logger = structlog.get_logger(__name__)
    await initialize_database(engine, logger, schema=Base.metadata, reset=True)
    async with Factory.standalone(config, engine) as factory:
        admin_service = factory.create_admin_service()
        async with factory.session.begin():
            try:
                sql = "DROP TABLE alembic_version"
                await factory.session.execute(text(sql))
            except ProgrammingError:
                # Ignore failures to drop the alembic_version table becuase it
                # doesn't exist.
                pass
        async with factory.session.begin():
            await admin_service.add_initial_admins(config.initial_admins)
        await factory._context.redis.flushdb()

    # Get Alembic configuration information.
    alembic_config = AlembicConfig("alembic.ini")
    alembic_scripts = ScriptDirectory.from_config(alembic_config)
    current_head = alembic_scripts.get_current_head()
    assert current_head

    def set_version(connection: Connection) -> None:
        context = MigrationContext.configure(connection)
        context.stamp(alembic_scripts, current_head)

    # Stamp the database with the current Alembic version. We have to do this
    # somewhat elaborately because the alembic.command interface cannot be run
    # inside an asyncio loop.
    async with engine.begin() as connection:
        await connection.run_sync(set_version)
    await engine.dispose()


@pytest_asyncio.fixture
def engine() -> AsyncEngine:
    """Create a database engine for testing.

    Previously, this fixture was session-scoped so that all tests could share
    a single connection pool and not constantly open and close connections to
    the database, which made the test suite run faster. However, this approach
    broke horribly with confusing asyncio and asyncpg errors when
    pytest-asyncio was upgraded from 0.21.1 to 0.23.2 and the maintenance
    burden doesn't seem worth it.
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


@pytest.fixture
def mock_firestore(tmp_path: Path) -> Iterator[MockFirestore]:
    """Configure Firestore UID/GID assignment and mock the Firestore API."""
    yield from patch_firestore()


@pytest.fixture
def mock_ldap() -> Iterator[MockLDAP]:
    """Replace the bonsai LDAP API with a mock class."""
    yield from patch_ldap()


@pytest.fixture
def mock_slack(
    config: Config, respx_mock: respx.Router
) -> MockSlackWebhook | None:
    """Mock a Slack webhook."""
    if not config.slack_webhook:
        return None
    return mock_slack_webhook(config.slack_webhook, respx_mock)


@pytest.fixture
def selenium_config(
    tmp_path: Path, driver: webdriver.Chrome
) -> Iterator[SeleniumConfig]:
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
    with run_app(tmp_path, config_path) as config:
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
