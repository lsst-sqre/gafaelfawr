"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import Depends, Form
from fastapi.responses import JSONResponse

from gafaelfawr.fastapi.auth import verified_session
from gafaelfawr.fastapi.dependencies import RequestContext, context
from gafaelfawr.fastapi.handlers import router
from gafaelfawr.session import (
    InvalidSessionHandleException,
    Session,
    SessionHandle,
)
from gafaelfawr.tokens import Token

__all__ = ["get_analyze", "post_analyze"]


class FormattedJSONResponse(JSONResponse):
    """The same as `~fastapi.JSONResponse` except formatted for humans."""

    def render(self, content: Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=4,
            sort_keys=True,
        ).encode()


@router.get("/auth/analyze", response_class=FormattedJSONResponse)
async def get_analyze(
    session: Session = Depends(verified_session),
    context: RequestContext = Depends(context),
) -> Dict[str, Any]:
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
    result = await analyze_handle(context, session.handle)
    context.logger.info("Analyzed user session")
    return result


@router.post("/auth/analyze", response_class=FormattedJSONResponse)
async def post_analyze(
    token: str = Form(...), context: RequestContext = Depends(context)
) -> Dict[str, Any]:
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
    try:
        handle = SessionHandle.from_str(token)
        result = await analyze_handle(context, handle)
        context.logger.info("Analyzed user-provided session handle")
        return result
    except InvalidSessionHandleException:
        verifier = context.factory.create_token_verifier()
        analysis = verifier.analyze_token(Token(encoded=token))
        context.logger.info("Analyzed user-provided token")
        return {"token": analysis}


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
