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
from cryptography.fernet import Fernet
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from safir.database import create_database_engine, initialize_database
from safir.dependencies.db_session import db_session_dependency
from safir.testing.slack import MockSlackWebhook, mock_slack_webhook
from seleniumwire import webdriver
from sqlalchemy import Connection
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.constants import COOKIE_NAME
from gafaelfawr.factory import Factory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.main import create_app
from gafaelfawr.models.state import State
from gafaelfawr.models.token import Token, TokenType
from gafaelfawr.schema import Base

from .pages.tokens import TokensPage
from .support.config import config_path, configure
from .support.constants import TEST_HOSTNAME
from .support.database import clear_alembic_version
from .support.firestore import MockFirestore, patch_firestore
from .support.ldap import MockLDAP, patch_ldap
from .support.selenium import SeleniumConfig, run_app, selenium_driver

_ISSUER_KEY = RSAKeyPair.generate()
"""RSA key pair for JWT issuance and verification.

Generating this takes a surprisingly long time when summed across every test,
so generate one statically at import time for each test run and use it for
every configuration file.
"""


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
    transport = ASGITransport(app=app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url=base_url) as client:
        yield client


@pytest.fixture
def config(monkeypatch: pytest.MonkeyPatch) -> Config:
    """Set up and return the default test configuration.

    The fixture always configures Gafealfawr for GitHub authentication, but it
    sets up the environment variables with secrets for other providers and
    user information sources so that the test case can switch later.

    Notes
    -----
    This fixture must not be async so that it can be used by the cli tests,
    which must not be async because the Click support starts its own asyncio
    loop.
    """
    oidc_server_key = _ISSUER_KEY.private_key_as_pem().decode()
    session_secret = Fernet.generate_key().decode()
    slack_webhook = "https://slack.example.com/webhook"
    monkeypatch.setenv("GAFAELFAWR_BOOTSTRAP_TOKEN", str(Token()))
    monkeypatch.setenv("GAFAELFAWR_CILOGON_CLIENT_SECRET", "oidc-secret")
    monkeypatch.setenv("GAFAELFAWR_GITHUB_CLIENT_SECRET", "github-secret")
    monkeypatch.setenv("GAFAELFAWR_OIDC_CLIENT_SECRET", "oidc-secret")
    monkeypatch.setenv("GAFAELFAWR_OIDC_SERVER_KEY", oidc_server_key)
    monkeypatch.setenv("GAFAELFAWR_SESSION_SECRET", session_secret)
    monkeypatch.setenv("GAFAELFAWR_SLACK_WEBHOOK", slack_webhook)
    return configure("github")


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

    # Stamp the database with the current Alembic version. Initializing the
    # database will not update the Aflembic version, so we have to do this
    # explicitly to ensure that there isn't any out-of-date schema information
    # left over from a previous test.
    #
    # We have to do this somewhat elaborately because the alembic.command
    # interface cannot be run inside an asyncio loop.
    await clear_alembic_version(engine)
    async with engine.begin() as connection:
        await connection.run_sync(set_version)
    await engine.dispose()


@pytest_asyncio.fixture
def engine(config: Config) -> AsyncEngine:
    """Create a database engine for testing.

    Previously, this fixture was session-scoped so that all tests could share
    a single connection pool and not constantly open and close connections to
    the database, which made the test suite run faster. However, this approach
    broke horribly with confusing asyncio and asyncpg errors when
    pytest-asyncio was upgraded from 0.21.1 to 0.23.2 and the maintenance
    burden doesn't seem worth it.
    """
    return create_database_engine(
        config.database_url, config.database_password.get_secret_value()
    )


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
    webhook = config.slack_webhook.get_secret_value()
    return mock_slack_webhook(webhook, respx_mock)


@pytest.fixture
def selenium_config(
    tmp_path: Path, config: Config, driver: webdriver.Chrome
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
    with run_app(tmp_path, config_path("selenium")) as selenium_config:
        cookie = State(token=selenium_config.token).to_cookie()
        driver.header_overrides = {"Cookie": f"{COOKIE_NAME}={cookie}"}

        # The synthetic cookie doesn't have a CSRF token, so we want to
        # replace it with a real cookie.  Do this by visiting the top-level
        # page of the UI and waiting for the token list to appear, which will
        # trigger fleshing out the state, and then dropping the header
        # override for subsequent calls so that the cookie set in the browser
        # will be used.
        driver.get(urljoin(selenium_config.url, "/auth/tokens/"))
        tokens_page = TokensPage(driver)
        tokens_page.get_tokens(TokenType.session)
        del driver.header_overrides

        yield selenium_config
