"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

import functools
import json
from typing import cast

from aiohttp import web
from aiohttp_session import get_session

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import RequestContext
from gafaelfawr.session import InvalidSessionHandleException, SessionHandle
from gafaelfawr.tokens import Token

__all__ = ["get_analyze", "post_analyze"]


@routes.get("/auth/analyze")
async def get_analyze(request: web.Request) -> web.Response:
    """Analyze a session handle from a web session.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.

    Raises
    ------
    aiohttp.web.HTTPException
        If the user is not logged in.
    """
    context = RequestContext.from_request(request)
    session = await get_session(request)
    if "handle" not in session:
        msg = "Not logged in"
        context.logger.warning(msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)
    handle = SessionHandle.from_str(session["handle"])
    session_store = context.factory.create_session_store(
        context.request, context.logger
    )
    result = await session_store.analyze_handle(handle)
    context.logger.info("Analyzed user session")
    formatter = functools.partial(json.dumps, sort_keys=True, indent=4)
    return web.json_response(result, dumps=formatter)


@routes.post("/auth/analyze")
async def post_analyze(request: web.Request) -> web.Response:
    """Analyze a token.

    Expects a POST with a single parameter, ``token``, which is either a
    session handle or a token.  Returns a JSON structure with details about
    that token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    context = RequestContext.from_request(request)
    data = await request.post()
    handle_or_token = cast(str, data["token"])

    try:
        handle = SessionHandle.from_str(handle_or_token)
        session_store = context.factory.create_session_store(
            context.request, context.logger
        )
        context.logger.info("Analyzed user-provided session handle")
        result = await session_store.analyze_handle(handle)
    except InvalidSessionHandleException:
        token = Token(encoded=handle_or_token)
        verifier = context.factory.create_token_verifier(
            context.request, context.logger
        )
        analysis = verifier.analyze_token(token)
        context.logger.info("Analyzed user-provided token")
        result = {"token": analysis}

    formatter = functools.partial(json.dumps, sort_keys=True, indent=4)
    return web.json_response(result, dumps=formatter)
