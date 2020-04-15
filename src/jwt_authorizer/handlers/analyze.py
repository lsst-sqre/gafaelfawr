"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from aiohttp import web
from aiohttp_session import get_session

from jwt_authorizer.analyze import analyze_ticket, analyze_token
from jwt_authorizer.handlers import routes
from jwt_authorizer.session import InvalidTicketException, Ticket
from jwt_authorizer.tokens import Token

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from jwt_authorizer.factory import ComponentFactory

__all__ = ["post_analyze"]


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
    config: Config = request.config_dict["jwt_authorizer/config"]
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]

    session = await get_session(request)
    prefix = config.session_store.ticket_prefix
    ticket = Ticket.from_str(prefix, session["ticket"])
    session_store = factory.create_session_store()
    verifier = factory.create_token_verifier(request)
    result = await analyze_ticket(ticket, prefix, session_store, verifier)
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
    config: Config = request.config_dict["jwt_authorizer/config"]
    factory: ComponentFactory = request.config_dict["jwt_authorizer/factory"]

    verifier = factory.create_token_verifier(request)
    prefix = config.session_store.ticket_prefix
    data = await request.post()
    ticket_or_token = cast(str, data["token"])

    try:
        ticket = Ticket.from_str(prefix, ticket_or_token)
        token_store = factory.create_session_store()
        result = await analyze_ticket(ticket, prefix, token_store, verifier)
    except InvalidTicketException:
        token = Token(encoded=ticket_or_token)
        analysis = await analyze_token(token, verifier)
        result = {"token": analysis}

    return web.json_response(result)
