"""Handlers for user-created tokens (``/auth/tokens``)."""

from __future__ import annotations

from functools import wraps
from typing import TYPE_CHECKING

from aiohttp import web
from aiohttp_csrf import csrf_protect, generate_token
from aiohttp_jinja2 import template
from aiohttp_session import get_session
from wtforms import BooleanField, Form, HiddenField, SubmitField

from gafaelfawr.handlers import routes
from gafaelfawr.handlers.util import (
    AuthChallenge,
    AuthError,
    AuthType,
    InvalidTokenException,
    verify_token,
)
from gafaelfawr.session import Session, SessionHandle

if TYPE_CHECKING:
    from aioredis import Redis
    from gafaelfawr.config import Config
    from gafaelfawr.factory import ComponentFactory
    from gafaelfawr.tokens import VerifiedToken
    from logging import Logger
    from multidict import MultiDictProxy
    from typing import Any, Awaitable, Callable, Dict, Optional, Union

    Route = Callable[[web.Request], Awaitable[Any]]
    AuthenticatedRoute = Callable[[web.Request, VerifiedToken], Awaitable[Any]]

__all__ = [
    "get_token_by_handle",
    "get_tokens",
    "get_tokens_new",
    "post_delete_token",
    "post_tokens_new",
]


def authenticated(route: AuthenticatedRoute) -> Route:
    """Decorator to mark a route as requiring authentication.

    The authorization token is extracted from the X-Auth-Request-Token header
    and verified, and then passed as an additional parameter to the wrapped
    function.  If the token is missing or invalid, returns a 401 error to the
    user.

    Parameters
    ----------
    route : `typing.Callable`
        The route that requires authentication.  The token is extracted from
        the incoming request headers, verified, and then passed as a second
        argument of type `gafaelfawr.tokens.VerifiedToken` to the route.

    Returns
    -------
    response : `typing.Callable`
        The decorator generator.

    Raises
    ------
    aiohttp.web.HTTPException
        If no token is present or the token cannot be verified.
    """

    @wraps(route)
    async def authenticated_route(request: web.Request) -> Any:
        config: Config = request.config_dict["gafaelfawr/config"]
        logger: Logger = request["safir/logger"]

        if not request.headers.get("X-Auth-Request-Token"):
            challenge = AuthChallenge(AuthType.Bearer, config.realm)
            headers = {"WWW-Authenticate": challenge.as_header()}
            msg = "No authentication token found"
            raise web.HTTPUnauthorized(headers=headers, reason=msg, text=msg)

        encoded_token = request.headers["X-Auth-Request-Token"]
        try:
            token = verify_token(request, encoded_token)
        except InvalidTokenException as e:
            error = "Failed to authenticate token"
            challenge = AuthChallenge(
                auth_type=AuthType.Bearer,
                realm=config.realm,
                error=AuthError.invalid_token,
                error_description=f"{error}: {str(e)}",
            )
            logger.warning(challenge.error_description)
            headers = {"WWW-Authenticate": challenge.as_header()}
            raise web.HTTPUnauthorized(
                headers=headers, reason=error, text=challenge.error_description
            )

        return await route(request, token)

    return authenticated_route


class AlterTokenForm(Form):
    """Form for altering an existing user token."""

    method_ = HiddenField("method_")
    csrf = HiddenField("_csrf")


def build_new_token_form(
    scopes: Dict[str, str],
    data: Optional[MultiDictProxy[Union[str, bytes, web.FileField]]] = None,
) -> Form:
    """Dynamically generates a form with checkboxes for scopes.

    Parameters
    ----------
    scopes : Dict[`str`, `str`]
        A mapping of scope names to descriptions to include in the form.
    data : MultiDictProxy[Union[`str`, `bytes`, FileField]], optional
        The submitted form data, if any.

    Returns
    -------
    form : `wtforms.Form`
        The generated form.
    """

    class NewTokenForm(Form):
        """Stub form, to which fields will be dynamically added."""

        csrf = HiddenField("_csrf")
        submit = SubmitField("Generate New Token")

    for scope, description in scopes.items():
        field = BooleanField(label=scope, description=description)
        setattr(NewTokenForm, scope, field)
    return NewTokenForm(data)


@routes.get("/auth/tokens", name="tokens")
@template("tokens.html")
@authenticated
async def get_tokens(
    request: web.Request, token: VerifiedToken
) -> Dict[str, object]:
    """Displays all tokens for the current user.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]

    session = await get_session(request)
    message = session.pop("message", None)
    session["csrf"] = await generate_token(request)

    token_store = factory.create_token_store(request)
    await token_store.expire_tokens(token.uid)
    user_tokens = await token_store.get_tokens(token.uid)
    forms = {}
    for user_token in user_tokens:
        form = AlterTokenForm()
        form.csrf.data = session["csrf"]
        forms[user_token.key] = form

    return {
        "message": message,
        "tokens": user_tokens,
        "forms": forms,
        "csrf_token": session["csrf"],
    }


@routes.get("/auth/tokens/new")
@template("new_token.html")
@authenticated
async def get_tokens_new(
    request: web.Request, token: VerifiedToken
) -> Dict[str, object]:
    """Return a form for creating a new token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    config: Config = request.config_dict["gafaelfawr/config"]

    scopes = {s: d for s, d in config.known_scopes.items() if s in token.scope}
    form = build_new_token_form(scopes)

    session = await get_session(request)
    session["csrf"] = await generate_token(request)

    return {
        "form": form,
        "scopes": scopes,
        "csrf_token": session["csrf"],
    }


@routes.post("/auth/tokens/new")
@csrf_protect
@authenticated
async def post_tokens_new(
    request: web.Request, token: VerifiedToken
) -> Dict[str, object]:
    """Create a new token based on form parameters.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    config: Config = request.config_dict["gafaelfawr/config"]
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]
    redis: Redis = request.config_dict["gafaelfawr/redis"]
    logger: Logger = request["safir/logger"]

    scopes = {s: d for s, d in config.known_scopes.items() if s in token.scope}
    form = build_new_token_form(scopes, await request.post())
    if not form.validate():
        msg = f"Form validation failed"
        logger.warning(msg)
        raise web.HTTPBadRequest(reason=msg, text=msg)

    scope = " ".join([s for s in scopes if form[s].data])
    issuer = factory.create_token_issuer()
    handle = SessionHandle()
    user_token = issuer.issue_user_token(token, scope=scope, jti=handle.key)

    session_store = factory.create_session_store(request)
    token_store = factory.create_token_store(request)
    user_session = Session.create(handle, user_token)
    pipeline = redis.pipeline()
    await session_store.store_session(user_session, pipeline)
    token_store.store_session(token.uid, user_session, pipeline)
    await pipeline.execute()

    message = (
        f"Your Newly Created Token. Keep these Secret!<br>\n"
        f"Token: {handle.encode()} <br>"
    )
    session = await get_session(request)
    session["message"] = message

    location = request.app.router["tokens"].url_for()
    raise web.HTTPFound(location)


@routes.get("/auth/tokens/{handle}")
@template("token.html")
@authenticated
async def get_token_by_handle(
    request: web.Request, token: VerifiedToken
) -> Dict[str, object]:
    """Displays information about a single token.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]
    handle = request.match_info["handle"]

    token_store = factory.create_token_store(request)
    user_token = None
    for entry in await token_store.get_tokens(token.uid):
        if entry.key == handle:
            user_token = entry
            break

    if not user_token:
        msg = f"No token with handle {handle} found"
        raise web.HTTPNotFound(reason=msg, text=msg)

    return {"token": user_token}


@routes.post("/auth/tokens/{handle}")
@csrf_protect
@authenticated
async def post_delete_token(
    request: web.Request, token: VerifiedToken
) -> web.Response:
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
    factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]
    redis: Redis = request.config_dict["gafaelfawr/redis"]
    handle = request.match_info["handle"]

    form = AlterTokenForm(await request.post())
    if not form.validate() or form.method_.data != "DELETE":
        msg = "Invalid deletion request"
        raise web.HTTPForbidden(reason=msg, text=msg)

    token_store = factory.create_token_store(request)
    session_store = factory.create_session_store(request)
    pipeline = redis.pipeline()
    success = await token_store.revoke_token(token.uid, handle, pipeline)
    if success:
        session_store.delete_session(handle, pipeline)
        await pipeline.execute()

    if success:
        message = f"Your token with the handle {handle} was deleted"
    else:
        message = "An error was encountered when deleting your token"
    session = await get_session(request)
    session["message"] = message

    location = request.app.router["tokens"].url_for()
    raise web.HTTPFound(location)
