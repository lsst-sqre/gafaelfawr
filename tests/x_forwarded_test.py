"""Test X-Forwarded-For parsing logic.

This file is heavily based on the test suite submitted upstream along with
this feature in https://github.com/aio-libs/aiohttp-remotes/pull/154.
"""

from __future__ import annotations

from ipaddress import ip_network
from typing import TYPE_CHECKING

import aiohttp_remotes
from aiohttp import web

from gafaelfawr.x_forwarded import XForwardedFiltered

if TYPE_CHECKING:
    from aiohttp.pytest_plugin.test_utils import TestClient
    from typing import Awaitable, Callable

    Handler = Callable[[web.Request], Awaitable[web.Response]]
    TestClientCallable = Callable[[web.Application], Awaitable[TestClient]]


async def setup_test(
    aiohttp_client: TestClientCallable,
    handler: Handler,
    middleware: XForwardedFiltered,
) -> TestClient:
    """Construct a test application with the given handler and middleware."""
    app = web.Application()
    app.router.add_get("/", handler)
    await aiohttp_remotes.setup(app, middleware)
    client = await aiohttp_client(app)
    return client


async def test_ok(aiohttp_client: TestClientCallable) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.host == "example.com"
        assert request.scheme == "https"
        assert request.secure
        assert request.remote == "10.10.10.10"
        return web.Response()

    middleware = XForwardedFiltered([ip_network("11.0.0.0/8")])
    client = await setup_test(aiohttp_client, handler, middleware)
    resp = await client.get(
        "/",
        headers={
            "X-Forwarded-For": "10.10.10.10, 11.11.11.11",
            "X-Forwarded-Proto": "https, http",
            "X-Forwarded-Host": "example.com",
        },
    )
    assert resp.status == 200


async def test_no_forwards(aiohttp_client: TestClientCallable) -> None:
    async def handler(request: web.Request) -> web.Response:
        url = client.make_url("/")
        host = url.host + ":" + str(url.port)
        assert request.host == host
        assert request.scheme == "http"
        assert not request.secure
        assert request.remote == "127.0.0.1"
        return web.Response()

    middleware = XForwardedFiltered([ip_network("127.0.0.1")])
    client = await setup_test(aiohttp_client, handler, middleware)
    resp = await client.get("/")
    assert resp.status == 200


async def test_all_filtered(aiohttp_client: TestClientCallable) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.host == "example.com"
        assert request.scheme == "https"
        assert request.secure
        assert request.remote == "10.10.10.10"
        return web.Response()

    middleware = XForwardedFiltered([ip_network("10.0.0.0/8")])
    client = await setup_test(aiohttp_client, handler, middleware)
    resp = await client.get(
        "/",
        headers={
            "X-Forwarded-For": "10.10.10.10, 10.0.0.1",
            "X-Forwarded-Proto": "https, http",
            "X-Forwarded-Host": "example.com",
        },
    )
    assert resp.status == 200


async def test_one_proto(aiohttp_client: TestClientCallable) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.host == "example.com"
        assert request.scheme == "https"
        assert request.secure
        assert request.remote == "10.10.10.10"
        return web.Response()

    middleware = XForwardedFiltered([ip_network("11.11.11.11")])
    client = await setup_test(aiohttp_client, handler, middleware)
    resp = await client.get(
        "/",
        headers={
            "X-Forwarded-For": "10.10.10.10, 11.11.11.11",
            "X-Forwarded-Proto": "https",
            "X-Forwarded-Host": "example.com",
        },
    )
    assert resp.status == 200


async def test_no_proto_or_host(aiohttp_client: TestClientCallable) -> None:
    async def handler(request: web.Request) -> web.Response:
        url = client.make_url("/")
        host = url.host + ":" + str(url.port)
        assert request.host == host
        assert request.scheme == "http"
        assert not request.secure
        assert request.remote == "10.10.10.10"
        return web.Response()

    middleware = XForwardedFiltered([ip_network("11.11.11.11")])
    client = await setup_test(aiohttp_client, handler, middleware)
    resp = await client.get(
        "/", headers={"X-Forwarded-For": "10.10.10.10, 11.11.11.11"}
    )
    assert resp.status == 200


async def test_too_many_headers(aiohttp_client: TestClientCallable) -> None:
    async def handler(request: web.Request) -> web.Response:
        assert request.host == "example.com"
        assert request.scheme == "https"
        assert request.secure
        assert request.remote == "10.10.10.10"
        return web.Response()

    middleware = XForwardedFiltered([ip_network("10.0.0.0/8")])
    client = await setup_test(aiohttp_client, handler, middleware)
    resp = await client.get(
        "/",
        headers=[
            ("X-Forwarded-For", "10.10.10.10"),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-Proto", "http"),
            ("X-Forwarded-Host", "example.com"),
        ],
    )
    assert resp.status == 200
