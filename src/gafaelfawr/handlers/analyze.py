"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

import functools
import json
from typing import TYPE_CHECKING, cast

from aiohttp import web

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.decorators import authenticated_session
from gafaelfawr.handlers.util import RequestContext
from gafaelfawr.session import InvalidSessionHandleException, SessionHandle
from gafaelfawr.tokens import Token

if TYPE_CHECKING:
    from typing import Any, Dict

    from gafaelfawr.sesion import Session

__all__ = ["get_analyze", "post_analyze"]


@routes.get("/auth/analyze")
@authenticated_session
async def get_analyze(request: web.Request, session: Session) -> web.Response:
    """Analyze a session handle from a web session.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    session : `gafaelfawr.session.Session`
        The authentication session.

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
    result = await analyze_handle(context, session.handle)
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
        result = await analyze_handle(context, handle)
        context.logger.info("Analyzed user-provided session handle")
    except InvalidSessionHandleException:
        token = Token(encoded=handle_or_token)
        verifier = context.factory.create_token_verifier()
        analysis = verifier.analyze_token(token)
        context.logger.info("Analyzed user-provided token")
        result = {"token": analysis}

    formatter = functools.partial(json.dumps, sort_keys=True, indent=4)
    return web.json_response(result, dumps=formatter)


async def analyze_handle(
    context: RequestContext, handle: SessionHandle
) -> Dict[str, Any]:
    """Analyze a session handle and return its expanded information.

    Parameters
    ----------
    context : `gafaelfawr.handlers.util.RequestContext`
        The request context.
    handle : `gafaelfawr.session.SessionHandle`
        The session handle to analyze.

    Returns
    -------
    output : Dict[`str`, Any]
        The contents of the session handle and its underlying session.
        This will include the session key and secret, the session it
        references, and the token that session contains.
    """
    output: Dict[str, Any] = {
        "handle": {"key": handle.key, "secret": handle.secret}
    }

    session_store = context.factory.create_session_store()
    session = await session_store.get_session(handle)
    if not session:
        output["errors"] = [f"No session found for {handle.encode()}"]
        return output

    created_at = session.created_at.strftime("%Y-%m-%d %H:%M:%S -0000")
    expires_on = session.expires_on.strftime("%Y-%m-%d %H:%M:%S -0000")
    output["session"] = {
        "email": session.email,
        "created_at": created_at,
        "expires_on": expires_on,
    }

    verifier = context.factory.create_token_verifier()
    output["token"] = verifier.analyze_token(session.token)

    return output
