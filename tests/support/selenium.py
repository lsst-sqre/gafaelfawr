"""Helper functions for Selenium tests."""

from __future__ import annotations

import errno
import logging
import os
import socket
import subprocess
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING

from seleniumwire import webdriver

from gafaelfawr.database import initialize_database
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.token import Token

if TYPE_CHECKING:
    from pathlib import Path
    from typing import Iterator

    from gafelfawr.config import Config

APP_TEMPLATE = """
import os
from datetime import timedelta
from unittest.mock import MagicMock
from urllib.parse import urlparse

import structlog
from fastapi_sqlalchemy import db

from gafaelfawr.database import initialize_database
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.dependencies.redis import redis_dependency
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.main import app
from gafaelfawr.models.token import TokenUserInfo
from tests.support.tokens import add_expired_session_token
from gafaelfawr.util import current_datetime

config_dependency.set_settings_path("{settings_path}")


@app.on_event("startup")
async def startup_event() -> None:
    config = config_dependency()
    logger = structlog.get_logger(config.safir.logger_name)
    user_info = TokenUserInfo(username="testuser", name="Test User", uid=1000)
    scopes = list(config.known_scopes.keys())

    # Mock out Redis if there is none running.
    if not os.environ.get("REDIS_6379_TCP_PORT"):
        import mockaioredis

        redis = await mockaioredis.create_redis_pool("")
        redis_dependency.set_redis(redis)

    # Initialize the database.  Non-SQLite databases need to be reset between
    # tests.
    should_reset = not urlparse(config.database_url).scheme == "sqlite"
    initialize_database(config, reset=should_reset)

    with db():
        # Add an expired token so that we can test display of expired tokens.
        await add_expired_session_token(
            user_info,
            scopes=scopes,
            ip_address="127.0.0.1",
            session=db.session,
        )

        # Add the valid session token.
        factory = ComponentFactory(
            config=config,
            redis=await redis_dependency(config),
            session=db.session,
            http_client=MagicMock(),
            logger=logger,
        )
        token_service = factory.create_token_service()
        token = await token_service.create_session_token(
            user_info, scopes=scopes, ip_address="127.0.0.1"
        )

    with open("{token_path}", "w") as f:
        f.write(str(token))
"""


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
    driver : `selenium.webdriver.Chrome`
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


@contextmanager
def run_app(tmp_path: Path, settings_path: Path) -> Iterator[SeleniumConfig]:
    """Run the application as a separate process for Selenium access.

    Parameters
    ----------
    tmp_path : `pathlib.Path`
        The temporary directory for testing.
    settings_path : `pathlib.Path`
        The path to the settings file.
    """
    config_dependency.set_settings_path(str(settings_path))
    config = config_dependency()
    initialize_database(config)

    token_path = tmp_path / "token"
    app_source = APP_TEMPLATE.format(
        settings_path=str(settings_path),
        token_path=str(token_path),
    )
    app_path = tmp_path / "testing.py"
    with app_path.open("w") as f:
        f.write(app_source)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]

    cmd = ["uvicorn", "--fd", "0", "testing:app"]
    logging.info("Starting server with command %s", " ".join(cmd))
    p = subprocess.Popen(
        cmd,
        cwd=str(tmp_path),
        stdin=s.fileno(),
        env={**os.environ, "PYTHONPATH": os.getcwd()},
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
