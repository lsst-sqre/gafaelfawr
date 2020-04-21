"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from aiohttp import web
from aiohttp_session import get_session

from jwt_authorizer.handlers import routes
from jwt_authorizer.session import InvalidSessionHandleException, SessionHandle
from jwt_authorizer.tokens import Token

if TYPE_CHECKING:
    from jwt_authorizer.factory import ComponentFactory

__all__ = ["get_analyze", "post_analyze"]


@routes.get("/auth/analyze")
async def get_analyze(request: web.Request) -> web.Response:
    """Analyze a ticket from a web session.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]

    session = await get_session(request)
    handle = SessionHandle.from_str(session["handle"])
    session_store = factory.create_session_store(request)
    result = await session_store.analyze_handle(handle)
    return web.json_response(result)


@routes.post("/auth/analyze")
async def post_analyze(request: web.Request) -> web.Response:
    """Analyze a token.

    Expects a POST with a single parameter, ``token``, which is either a
    ticket or a full token.  Returns a JSON structure with details about that
    token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]

    data = await request.post()
    handle_or_token = cast(str, data["token"])

    try:
        handle = SessionHandle.from_str(handle_or_token)
        session_store = factory.create_session_store(request)
        result = await session_store.analyze_handle(handle)
    except InvalidSessionHandleException:
        token = Token(encoded=handle_or_token)
        verifier = factory.create_token_verifier()
        analysis = verifier.analyze_token(token)
        result = {"token": analysis}

    return web.json_response(result)
