"""Helper functions for Selenium tests."""

from __future__ import annotations

import errno
import logging
import os
import socket
import subprocess
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI
from safir.database import create_database_engine
from seleniumwire import webdriver

from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency
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
    be run with its display enabled.  This is useful for debugging Selenium
    tests.

    Uses a 1920x1080 window size, which emulates a reasonably modern desktop
    or laptop.  This (not a mobile device) is expected to be the normal use
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

    # Required or Chromium 83 will not start.  Various pages on-line insist
    # that this only happens if Chrome or Chromium is run as root and the
    # better solution is to not run it as root, but this appears not to be
    # true.  Chromium immediately crashes for me without this option, no
    # matter what user it is run as, when run via Selenium.
    options.add_argument("no-sandbox")

    # Isolate the running Chrome or Chromium instance from any local user
    # configuration or extensions if running on a developer system instead of
    # in a clean CI environment.
    options.add_argument("disable-extensions")
    options.add_argument("incognito")

    # selenium-wire, which we use to inject an authentication token during
    # tests without having to go through a login process, works by injecting
    # proxy configuration into Chrome and then starting a local proxy that
    # manipulates requests and responses.  However, Chrome (at least Chromium
    # 83) bypasses all proxies for accesses to localhost by default.  This is
    # the magic incantation to tell Chrome to use the proxy even for localhost
    # accesses.  See https://github.com/wkeeling/selenium-wire/issues/157.
    options.add_argument("proxy-bypass-list=<-loopback>")

    driver = webdriver.Chrome(options=options)
    driver.implicitly_wait(1)
    return driver


def _wait_for_server(port: int, timeout: float = 5.0) -> None:
    """Wait until a server accepts connections on the specified port."""
    deadline = time.time() + timeout
    while True:
        socket_timeout = deadline - time.time()
        if socket_timeout < 0.0:
            assert False, f"Server did not start on port {port} in {timeout}s"
        try:
            s = socket.socket()
            s.settimeout(socket_timeout)
            s.connect(("localhost", port))
        except socket.timeout:
            pass
        except socket.error as e:
            if e.errno not in [errno.ETIMEDOUT, errno.ECONNREFUSED]:
                raise
        else:
            s.close()
            return
        time.sleep(0.1)


async def _selenium_startup(token_path: Path) -> None:
    """Startup hook for the app run in Selenium testing mode."""
    config = await config_dependency()
    user_info = TokenUserInfo(username="testuser", name="Test User", uid=1000)
    scopes = list(config.known_scopes.keys())

    engine = create_database_engine(
        config.database_url, config.database_password
    )
    async with Factory.standalone(config, engine) as factory:
        async with factory.session.begin():
            # Add an expired token so that we can test display of expired
            # tokens.
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

    token_path.write_text(str(token))


def selenium_create_app() -> FastAPI:
    """Create the FastAPI app that Selenium should run.

    This is the same as the main Gafaelfawr app but with an additional startup
    handler that initializes some tokens in Redis.  This setup must be done
    inside the spawned app in case the Redis in question is a memory-only mock
    Redis.

    Notes
    -----
    This function modifies the main Gafaelfawr app in place, so it must only
    be called by uvicorn in the separate process spawned by run_app.  If it is
    run in the main pytest process, it will break other tests.
    """
    app = create_app()
    token_path = Path(os.environ["GAFAELFAWR_TEST_TOKEN_PATH"])

    @app.on_event("startup")
    async def selenium_startup_event() -> None:
        await _selenium_startup(token_path)

    return app


@asynccontextmanager
async def run_app(
    tmp_path: Path, config_path: Path
) -> AsyncIterator[SeleniumConfig]:
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
    config = await config_dependency()
    token_path = tmp_path / "token"

    # Create the socket that the app will listen on.
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]

    # Spawn the app in a separate process using uvicorn.
    cmd = [
        "uvicorn",
        "--fd",
        "0",
        "--factory",
        "tests.support.selenium:selenium_create_app",
    ]
    logging.info("Starting server with command %s", " ".join(cmd))
    p = subprocess.Popen(
        cmd,
        cwd=str(tmp_path),
        stdin=s.fileno(),
        env={
            **os.environ,
            "GAFAELFAWR_CONFIG_PATH": str(config_path),
            "GAFAELFAWR_TEST_TOKEN_PATH": str(token_path),
            "PYTHONPATH": os.getcwd(),
        },
    )
    s.close()

    logging.info("Waiting for server to start")
    _wait_for_server(port)

    try:
        selenium_config = SeleniumConfig(
            config=config,
            token=Token.from_str(token_path.read_text()),
            url=f"http://localhost:{port}",
        )
        yield selenium_config
    finally:
        p.terminate()
