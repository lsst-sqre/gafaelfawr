"""Helper functions for Selenium tests."""

from __future__ import annotations

import asyncio
import os
from typing import TYPE_CHECKING

from seleniumwire import webdriver

if TYPE_CHECKING:
    from typing import Callable, TypeVar

    T = TypeVar("T")


async def run(f: Callable[[], T]) -> T:
    """Run a function async.

    Takes a synchronous function and runs it async in the default thread pool.
    Used primarily to wrap Selenium calls that may take actions rather than
    just inspect already-returned pages.

    Parameters
    ----------
    f : `typing.Callable`
        The function to run.

    Returns
    -------
    ret : `typing.Any`
        The return value of the function.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, f)


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

    return webdriver.Chrome(options=options)
