"""Helper functions for Selenium tests."""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated

from click.testing import CliRunner
from fastapi import Depends, FastAPI
from safir.database import create_database_engine
from safir.testing.uvicorn import spawn_uvicorn
from selenium import webdriver

from gafaelfawr.cli import main
from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.factory import Factory
from gafaelfawr.main import create_app
from gafaelfawr.models.token import Token, TokenUserInfo

from .tokens import add_expired_session_token


@dataclass
class SeleniumConfig:
    """Information about the running server at which Selenium can point."""

    config: Config
    """The config that the server is running with."""

    token: Token
    """A valid authentication token for the running server."""

    url: str
    """The URL at which to contact the server."""


def selenium_driver() -> webdriver.Chrome:
    """Create a driver for Selenium testing.

    If the environment variable ``HEADLESS`` is set to false, the driver will
    be run with its display enabled. This is useful for debugging Selenium
    tests.

    Uses a 1920x1080 window size, which emulates a reasonably modern desktop
    or laptop. This (not a mobile device) is expected to be the normal use
    case for Gafaelfawr.

    Returns
    -------
    selenium.webdriver.Chrome
        The web driver to use in Selenium tests.
    """
    options = webdriver.ChromeOptions()
    if os.environ.get("HEADLESS", "true") != "false":
        options.add_argument("headless")
    options.add_argument("window-size=1920,1080")

    # Required or Chromium 83 will not start. Various pages on-line insist
    # that this only happens if Chrome or Chromium is run as root and the
    # better solution is to not run it as root, but this appears not to be
    # true. Chromium immediately crashes for me without this option, no matter
    # what user it is run as, when run via Selenium.
    options.add_argument("no-sandbox")

    # Isolate the running Chrome or Chromium instance from any local user
    # configuration or extensions if running on a developer system instead of
    # in a clean CI environment.
    options.add_argument("disable-extensions")
    options.add_argument("incognito")

    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(1)
    return driver


async def _selenium_startup(app: FastAPI, token_path: Path) -> None:
    """Startup hook for the app run in Selenium testing mode."""
    config = await config_dependency()
    user_info = TokenUserInfo(username="testuser", name="Test User", uid=1000)
    scopes = set(config.known_scopes.keys())

    # Set up some additional tokens.
    engine = create_database_engine(
        config.database_url, config.database_password
    )
    async with Factory.standalone(config, engine) as factory:
        async with factory.session.begin():
            # Add an expired token for testing display of expired tokens.
            await add_expired_session_token(
                user_info,
                scopes=scopes,
                ip_address="127.0.0.1",
                session=factory.session,
            )

        # Add the valid session token.
        token_service = factory.create_token_service()
        token = await token_service.create_session_token(
            user_info, scopes=scopes, ip_address="127.0.0.1"
        )
    await engine.dispose()

    # Add a special route to set a cookie in the browser with the session
    # token so that all subsequent interactions act as if the user had logged
    # on normally.
    @app.get("/selenium-login")
    async def set_token(
        context: Annotated[RequestContext, Depends(context_dependency)],
    ) -> dict[str, str]:
        context.state.token = token
        return {"status": "ok"}

    # Also stuff the token in a file so that the test suite knows what it is.
    token_path.write_text(str(token))


def selenium_create_app() -> FastAPI:
    """Create the FastAPI app that Selenium should run.

    This is the same as the main Gafaelfawr app but with an additional startup
    handler that initializes some tokens in Redis.
    """
    token_path = Path(os.environ["GAFAELFAWR_TEST_TOKEN_PATH"])

    async def selenium_startup(app: FastAPI) -> None:
        await _selenium_startup(app, token_path)

    return create_app(extra_startup=selenium_startup)


@contextmanager
def run_app(tmp_path: Path, config_path: Path) -> Iterator[SeleniumConfig]:
    """Run the application as a separate process for Selenium access.

    Must be used as an async context manager.

    Parameters
    ----------
    tmp_path
        The temporary directory for testing.
    config_path
        The path to the configuration file.

    Yields
    ------
    SeleniumConfig
        The Selenium configuration.
    """
    config_dependency.set_config_path(config_path)
    config = config_dependency.config()
    token_path = tmp_path / "token"

    # Use gafaelfawr init to set up the database, since this will stamp it
    # with the correct Alembic head and we enable schema checking during
    # startup.
    runner = CliRunner()
    result = runner.invoke(main, ["init"], catch_exceptions=False)
    assert result.exit_code == 0

    # Start the server with the necessary files to do Alembic validation.
    shutil.copyfile("alembic.ini", tmp_path / "alembic.ini")
    shutil.copytree("alembic", tmp_path / "alembic")
    copy_env = {
        k: v for k, v in os.environ.items() if k.startswith("GAFAELFAWR_")
    }
    uvicorn = spawn_uvicorn(
        working_directory=tmp_path,
        factory="tests.support.selenium:selenium_create_app",
        timeout=10.0,
        env={
            "GAFAELFAWR_CONFIG_PATH": str(config_path),
            "GAFAELFAWR_TEST_TOKEN_PATH": str(token_path),
            **copy_env,
        },
    )

    # Return the configuration, terminating the server on any failure.
    try:
        yield SeleniumConfig(
            config=config,
            token=Token.from_str(token_path.read_text()),
            url=uvicorn.url,
        )
    finally:
        uvicorn.process.terminate()
