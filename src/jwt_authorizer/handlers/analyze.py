"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from aiohttp import web

from jwt_authorizer.analyze import analyze_ticket, analyze_token
from jwt_authorizer.handlers import routes
from jwt_authorizer.session import (
    InvalidTicketException,
    Ticket,
    create_session_store,
)
from jwt_authorizer.verify import create_token_verifier

if TYPE_CHECKING:
    from jwt_authorizer.config import Config

__all__ = ["post_analyze"]


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
    config: Config = request.config_dict["jwt_authorizer/config"]

    verifier = create_token_verifier(request)
    prefix = config.session_store.ticket_prefix
    data = await request.post()
    ticket_or_token = cast(str, data["token"])

    try:
        ticket = Ticket.from_str(prefix, ticket_or_token)
        token_store = create_session_store(request)
        result = await analyze_ticket(ticket, prefix, token_store, verifier)
    except InvalidTicketException:
        analysis = await analyze_token(ticket_or_token, verifier)
        result = {"token": analysis}

    return web.json_response(result)
