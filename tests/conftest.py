"""Test fixtures."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from urllib.parse import urljoin

import pytest
import pytest_asyncio
import respx
import structlog
from asgi_lifespan import LifespanManager
from cryptography.fernet import Fernet
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from safir.database import create_database_engine, stamp_database_async
from safir.testing.slack import MockSlackWebhook, mock_slack_webhook
from selenium import webdriver
from sqlalchemy.ext.asyncio import AsyncEngine

from gafaelfawr.config import Config
from gafaelfawr.database import initialize_gafaelfawr_database
from gafaelfawr.factory import Factory
from gafaelfawr.keypair import RSAKeyPair
from gafaelfawr.main import create_app
from gafaelfawr.models.token import Token

from .support.config import config_path, configure
from .support.constants import TEST_HOSTNAME
from .support.firestore import MockFirestore, patch_firestore
from .support.ldap import MockLDAP, patch_ldap
from .support.selenium import SeleniumConfig, run_app, selenium_driver

_ISSUER_KEY = RSAKeyPair.generate()
"""RSA key pair for JWT issuance and verification.

Generating this takes a surprisingly long time when summed across every test,
so generate one statically at import time for each test run and use it for
every configuration file.
"""


@pytest.fixture(autouse=True)
def environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set default values of environment variables for testing."""
    monkeypatch.setenv("GAFAELFAWR_BASE_URL", f"https://{TEST_HOSTNAME}")
    monkeypatch.setenv(
        "GAFAELFAWR_BASE_INTERNAL_URL",
        "http://gafaelfawr.gafaelfawr.svc.cluster.local:8080",
    )


@pytest_asyncio.fixture
async def app(
    empty_database: None, mock_slack: MockSlackWebhook | None
) -> AsyncIterator[FastAPI]:
    """Return a configured test application.

    Wraps the application in a lifespan manager so that startup and shutdown
    events are sent during test execution.
    """
    app = create_app(validate_schema=False)
    async with LifespanManager(app):
        yield app


@pytest_asyncio.fixture
async def client(app: FastAPI) -> AsyncIterator[AsyncClient]:
    """Return an ``httpx.AsyncClient`` configured to talk to the test app."""
    async with AsyncClient(
        base_url=f"https://{TEST_HOSTNAME}",
        headers={
            "X-Original-Method": "GET",
            "X-Original-URL": "https://foo.example.com/bar",
        },
        transport=ASGITransport(app=app),
    ) as client:
        yield client


@pytest.fixture
def config(monkeypatch: pytest.MonkeyPatch) -> Config:
    """Set up and return the default test configuration.

    The fixture always configures Gafealfawr for GitHub authentication, but it
    sets up the environment variables with secrets for other providers and
    user information sources so that the test case can switch later. Metrics
    are always disabled.

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
    await initialize_gafaelfawr_database(config, logger, engine, reset=True)
    async with Factory.standalone(config, engine) as factory:
        await factory._context.ephemeral_redis.flushdb()
        await factory._context.persistent_redis.flushdb()
    await stamp_database_async(engine)


@pytest.fixture
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
        config.database_url, config.database_password
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
        driver.get(urljoin(selenium_config.url, "/selenium-login"))
        yield selenium_config
