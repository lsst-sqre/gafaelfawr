"""Tests for the /logout route."""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

from tests.setup import SetupTest

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from pathlib import Path


async def test_logout(tmp_path: Path, aiohttp_client: TestClient) -> None:
    setup = await SetupTest.create(tmp_path, environment="github")
    client = await aiohttp_client(setup.app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        params={"rd": f"https://{client.host}"},
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub, which will set the authentication
    # cookie.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303

    # Confirm that we're logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status == 200

    # Go to /logout without specifying a redirect URL and check the redirect.
    r = await client.get("/logout", allow_redirects=False)
    assert r.status == 303
    assert r.headers["Location"] == setup.config.after_logout_url

    # Confirm that we're no longer logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status == 401


async def test_logout_with_url(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path, environment="github")
    client = await aiohttp_client(setup.app)

    # Simulate the initial authentication request.
    r = await client.get(
        "/login",
        params={"rd": f"https://{client.host}"},
        allow_redirects=False,
    )
    assert r.status == 303
    url = urlparse(r.headers["Location"])
    query = parse_qs(url.query)

    # Simulate the return from GitHub, which will set the authentication
    # cookie.
    r = await client.get(
        "/login",
        params={"code": "some-code", "state": query["state"][0]},
        allow_redirects=False,
    )
    assert r.status == 303

    # Confirm that we're logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status == 200

    # Go to /logout with a redirect URL and check the redirect.
    redirect_url = f"https://{client.host}:4444/logged-out"
    r = await client.get(
        "/logout", params={"rd": redirect_url}, allow_redirects=False
    )
    assert r.status == 303
    assert r.headers["Location"] == redirect_url

    # Confirm that we're no longer logged in.
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status == 401


async def test_logout_not_logged_in(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    r = await client.get("/logout", allow_redirects=False)
    assert r.status == 303
    assert r.headers["Location"] == setup.config.after_logout_url
    r = await client.get("/auth", params={"scope": "read:all"})
    assert r.status == 401


async def test_logout_bad_url(
    tmp_path: Path, aiohttp_client: TestClient
) -> None:
    setup = await SetupTest.create(tmp_path)
    client = await aiohttp_client(setup.app)

    r = await client.get(
        "/logout", params={"rd": "https://example.com/"}, allow_redirects=False
    )
    assert r.status == 400
