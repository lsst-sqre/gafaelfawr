"""Handlers for user-created tokens (``/auth/tokens``)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web
from aiohttp_csrf import csrf_protect, generate_token
from aiohttp_jinja2 import template
from aiohttp_session import get_session
from jwt import PyJWTError
from wtforms import BooleanField, Form, HiddenField, SubmitField

from jwt_authorizer.authnz import authenticate
from jwt_authorizer.handlers import routes
from jwt_authorizer.handlers.util import unauthorized
from jwt_authorizer.issuer import TokenIssuer
from jwt_authorizer.session import SessionStore
from jwt_authorizer.tokens import TokenStore

if TYPE_CHECKING:
    from aioredis import Redis
    from jwt_authorizer.config import Config
    from logging import Logger
    from multidict import MultiDictProxy
    from typing import Dict, Optional, Union

__all__ = [
    "get_token_by_handle",
    "get_tokens",
    "get_tokens_new",
    "post_delete_token",
    "post_tokens_new",
]


class AlterTokenForm(Form):
    """Form for altering an existing user token."""

    method_ = HiddenField("method_")
    csrf = HiddenField("_csrf")


def api_capabilities_token_form(
    capabilities: Dict[str, str],
    data: Optional[MultiDictProxy[Union[str, bytes, web.FileField]]] = None,
) -> Form:
    """Dynamically generates a form with checkboxes for capabilities.

    Parameters
    ----------
    capabilities : Dict[`str`, `str`]
        A mapping of capability names to descriptions to include in the form.
    data : MultiDictProxy[Union[`str`, `bytes`, FileField]], optional
        The submitted form data, if any.

    Returns
    -------
    form : `wtforms.Form`
        The generated form.
    """

    class NewCapabilitiesToken(Form):
        """Stub form, to which fields will be dynamically added."""

        submit = SubmitField("Generate New Token")

    NewCapabilitiesToken.capability_names = list(capabilities)
    for capability, description in capabilities.items():
        field = BooleanField(label=capability, description=description)
        setattr(NewCapabilitiesToken, capability, field)
    return NewCapabilitiesToken(data)


@routes.get("/auth/tokens", name="tokens")
@template("tokens.html")
async def get_tokens(request: web.Request) -> Dict[str, object]:
    """Displays all tokens for the current user.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : Dict[`str`, `object`]
        Form variables that are processed by the template decorator, which
        turns them into an `aiohttp.web.Response`.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    redis: Redis = request.config_dict["jwt_authorizer/redis"]
    logger: Logger = request["safir/logger"]

    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = await authenticate(request, encoded_token)
    except PyJWTError as e:
        logger.exception("Failed to authenticate token")
        raise unauthorized(request, "Invalid token", str(e))

    session = await get_session(request)
    message = session.pop("message", None)
    session["csrf"] = await generate_token(request)

    token_store = TokenStore(redis, config.uid_key)
    user_id = decoded_token[config.uid_key]
    user_tokens = await token_store.get_tokens(user_id)
    forms = {}
    for user_token in user_tokens:
        form = AlterTokenForm()
        form.csrf.data = session["csrf"]
        forms[user_token["jti"]] = form

    return {
        "message": message,
        "tokens": user_tokens,
        "forms": forms,
        "csrf_token": session["csrf"],
    }


@routes.get("/auth/tokens/new")
@template("new_token.html")
async def get_tokens_new(request: web.Request) -> Dict[str, object]:
    """Return a form for creating a new token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : Dict[`str`, `object`]
        Form variables that are processed by the template decorator, which
        turns them into an `aiohttp.web.Response`.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    logger: Logger = request["safir/logger"]

    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        await authenticate(request, encoded_token)
    except PyJWTError as e:
        logger.exception("Failed to authenticate token")
        raise unauthorized(request, "Invalid token", str(e))

    form = api_capabilities_token_form(config.known_capabilities)

    session = await get_session(request)
    session["csrf"] = await generate_token(request)

    return {
        "form": form,
        "capabilities": config.known_capabilities,
        "csrf_token": session["csrf"],
    }


@routes.post("/auth/tokens/new")
@csrf_protect
@template("new_token.html")
async def post_tokens_new(request: web.Request) -> Dict[str, object]:
    """Create a new token based on form parameters.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request, normally from nginx's ``auth_request``
        directive.

    Returns
    -------
    response : Dict[`str`, `object`]
        Form variables that are processed by the template decorator, which
        turns them into an `aiohttp.web.Response`.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    redis: Redis = request.config_dict["jwt_authorizer/redis"]
    logger: Logger = request["safir/logger"]

    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = await authenticate(request, encoded_token)
    except PyJWTError as e:
        logger.exception("Failed to authenticate token")
        raise unauthorized(request, "Invalid token", str(e))

    capabilities = config.known_capabilities
    form = api_capabilities_token_form(capabilities, await request.post())

    if not form.validate():
        return {"form": form, "capabilities": capabilities}

    new_capabilities = []
    for capability in capabilities:
        if form[capability].data:
            new_capabilities.append(capability)
    scope = " ".join(new_capabilities)
    new_token: Dict[str, object] = {"scope": scope}
    email = decoded_token.get("email")
    user = decoded_token.get(config.username_key)
    uid = decoded_token.get(config.uid_key)
    if email:
        new_token["email"] = email
    if user:
        new_token[config.username_key] = user
    if uid:
        new_token[config.uid_key] = uid

    # FIXME: Copies groups. Useful for WebDAV, maybe not necessary
    #
    # new_token['isMemberOf'] = decoded_token['isMemberOf']

    ticket_prefix = config.session_store.ticket_prefix
    session_store = SessionStore(
        ticket_prefix, config.session_store.oauth2_proxy_secret, redis
    )
    issuer = TokenIssuer(config.issuer, ticket_prefix, session_store, redis)
    token_store = TokenStore(redis, config.uid_key)
    ticket = await issuer.issue_user_token(new_token, token_store)

    message = (
        f"Your Newly Created Token. Keep these Secret!<br>\n"
        f"Token: {ticket.encode(ticket_prefix)} <br>"
    )
    session = await get_session(request)
    session["message"] = message

    location = request.app.router["tokens"].url_for()
    raise web.HTTPFound(location)


@routes.get("/auth/tokens/{handle}")
@template("token.html")
async def get_token_by_handle(request: web.Request) -> Dict[str, object]:
    """Displays information about a single token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : Dict[`str`, `object`]
        Form variables that are processed by the template decorator, which
        turns them into an `aiohttp.web.Response`.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    redis: Redis = request.config_dict["jwt_authorizer/redis"]
    logger: Logger = request["safir/logger"]
    handle = request.match_info["handle"]

    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = await authenticate(request, encoded_token)
    except PyJWTError as e:
        logger.exception("Failed to authenticate token")
        raise unauthorized(request, "Invalid token", str(e))

    token_store = TokenStore(redis, config.uid_key)
    user_id = decoded_token[config.uid_key]
    user_tokens = {t["jti"]: t for t in await token_store.get_tokens(user_id)}
    user_token = user_tokens[handle]

    return {"token": user_token}


@routes.post("/auth/tokens/{handle}")
@csrf_protect
@template("token.html")
async def post_delete_token(request: web.Request) -> Dict[str, object]:
    """Deletes a single token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : Dict[`str`, `object`]
        Form variables that are processed by the template decorator, which
        turns them into an `aiohttp.web.Response`.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    redis: Redis = request.config_dict["jwt_authorizer/redis"]
    logger: Logger = request["safir/logger"]
    handle = request.match_info["handle"]

    try:
        encoded_token = request.headers["X-Auth-Request-Token"]
        decoded_token = await authenticate(request, encoded_token)
    except PyJWTError as e:
        logger.exception("Failed to authenticate token")
        raise unauthorized(request, "Invalid token", str(e))

    token_store = TokenStore(redis, config.uid_key)
    user_id = decoded_token[config.uid_key]
    user_tokens = {t["jti"]: t for t in await token_store.get_tokens(user_id)}
    user_token = user_tokens[handle]

    form = AlterTokenForm(await request.post())
    if not form.validate() or form.method_.data != "DELETE":
        return {"token": user_token}

    token_store = TokenStore(redis, config.uid_key)
    pipeline = redis.pipeline()
    success = await token_store.revoke_token(user_id, handle, pipeline)
    if success:
        pipeline.delete(handle)
        await pipeline.execute()

    if success:
        message = f"Your token with the ticket_id {handle} was deleted"
    else:
        message = "An error was encountered when deleting your token"
    session = await get_session(request)
    session["message"] = message

    location = request.app.router["tokens"].url_for()
    raise web.HTTPFound(location)
