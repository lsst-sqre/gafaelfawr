"""Utility functions for external routes."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import jwt
from aiohttp import web

from gafaelfawr.exceptions import (
    InvalidRequestError,
    InvalidTokenError,
    OAuthBearerError,
    OAuthError,
)
from gafaelfawr.factory import ComponentFactory
from gafaelfawr.tokens import Token

if TYPE_CHECKING:
    from typing import Optional
    from urllib.parse import ParseResult

    from aiohttp import ClientSession
    from aioredis import Redis
    from cachetools import TTLCache
    from structlog import BoundLogger

    from gafaelfawr.config import Config
    from gafaelfawr.tokens import VerifiedToken

__all__ = [
    "AuthChallenge",
    "AuthError",
    "AuthType",
    "RequestContext",
    "validate_return_url",
    "verify_token",
]


@dataclass
class RequestContext:
    """Holds the incoming request and its surrounding context.

    The primary reason for the existence of this class is to allow the
    functions involved in request processing to repeated rebind the request
    logger to include more information, without having to pass both the
    request and the logger separately to every function.
    """

    request: web.Request
    """The incoming request."""

    config: Config
    """Gafaelfawr's configuration."""

    logger: BoundLogger
    """The request logger, rebound with discovered context."""

    redis: Redis
    """Connection pool to use to talk to Redis."""

    @classmethod
    def from_request(cls, request: web.Request) -> RequestContext:
        """Construct a RequestContext from an incoming request.

        Parameters
        ----------
        request : aiohttp.web.Request
            The incoming request.

        Returns
        -------
        context : RequestContext
            The newly-created context.
        """
        config: Config = request.config_dict["gafaelfawr/config"]
        redis: Redis = request.config_dict["gafaelfawr/redis"]
        logger: BoundLogger = request["safir/logger"]

        return cls(request=request, config=config, logger=logger, redis=redis)

    @property
    def factory(self) -> ComponentFactory:
        """A factory for constructing Gafaelfawr components.

        This is constructed on the fly at each reference to ensure that we get
        the latest logger, which may have additional bound context.
        """
        key_cache: TTLCache = self.request.config_dict["gafaelfawr/key_cache"]

        # Tests inject an override http_session in the config dict.
        http_session: ClientSession = self.request.config_dict.get(
            "safir/http_session"
        )
        if not http_session:
            http_session = self.request["safir/http_session"]

        return ComponentFactory(
            config=self.config,
            redis=self.redis,
            key_cache=key_cache,
            http_session=http_session,
            logger=self.logger,
        )

    def rebind_logger(self, **values: Optional[str]) -> None:
        """Add the given values to the logging context.

        Also updates the logging context stored in the request object in case
        the request context later needs to be recreated from the request.

        Parameters
        ----------
        **values : `str` or `None`
            Additional values that should be added to the logging context.
        """
        self.logger = self.logger.bind(**values)
        self.request["safir/logger"] = self.logger


class AuthType(Enum):
    """Authentication types for the WWW-Authenticate header."""

    Basic = auto()
    Bearer = auto()


class AuthError(Enum):
    """Valid authentication errors for a WWW-Authenticate header.

    Defined in RFC 6750.
    """

    invalid_request = auto()
    invalid_token = auto()
    insufficient_scope = auto()


@dataclass
class AuthChallenge:
    """Represents the components of a WWW-Authenticate header."""

    auth_type: AuthType
    """The authentication type (the first part of the header)."""

    realm: str
    """The value of the realm attribute."""

    error: Optional[AuthError] = None
    """The value of the error attribute if present."""

    error_description: Optional[str] = None
    """The value of the error description attribute if present."""

    scope: Optional[str] = None
    """The value of the scope attribute if present."""

    def as_header(self) -> str:
        """Construct the WWW-Authenticate header for this challenge.

        Returns
        -------
        header : `str`
            Contents of the WWW-Authenticate header.
        """
        if self.auth_type == AuthType.Basic or not self.error:
            return f'{self.auth_type.name} realm="{self.realm}"'

        error_description = self.error_description
        if error_description:
            # Strip invalid characters from the description.
            error_description = re.sub(r'["\\]', "", error_description)
        info = f'realm="{self.realm}", error="{self.error.name}"'
        if error_description:
            info += f', error_description="{error_description}"'
        if self.scope:
            info += f', scope="{self.scope}"'
        return f"{self.auth_type.name} {info}"


def generate_challenge(
    context: RequestContext, auth_type: AuthType, exc: OAuthBearerError
) -> web.HTTPException:
    """Convert an exception into an HTTP error with ``WWW-Authenticate``.

    Parameters
    ----------
    context : `RequestContext`
        The context of the incoming request.
    auth_type : `AuthType`
        The type of authentication to request.
    exc : `gafaelfawr.exceptions.OAuthBearerError`
        An exception representing a bearer token error.

    Returns
    -------
    aiohttp.web.HTTPException
        A prepopulated `~aiohttp.web.HTTPException` object ready for raising.
        The headers will contain a ``WWW-Authenticate`` challenge.
    """
    context.logger.warning("%s", exc.message, error=str(exc))
    challenge = AuthChallenge(
        auth_type=auth_type,
        realm=context.config.realm,
        error=AuthError[exc.error],
        error_description=str(exc),
    )
    headers = {"WWW-Authenticate": challenge.as_header()}
    return exc.exception(headers=headers, reason=exc.message, text=str(exc))


def generate_json_response(
    context: RequestContext, exc: OAuthError
) -> web.Response:
    """Convert an exception into an HTTP error with a JSON body.

    Parameters
    ----------
    context : `RequestContext`
        The context of the incoming request.
    exc : `gafaelfawr.exceptions.OAuthError`
        An exception representing an OAuth 2.0 or OpenID Connect error.

    Returns
    -------
    web.Response
        A JSON response with status 400.
    """
    context.logger.warning("%s", exc.message, error=str(exc))
    response = {
        "error": exc.error,
        "error_description": exc.message if exc.hide_error else str(exc),
    }
    return web.json_response(response, status=400)


def parse_authorization(
    context: RequestContext, *, allow_basic: bool = False
) -> Optional[str]:
    """Find a handle or token in the Authorization header.

    Supports either ``Bearer`` or (optionally) ``Basic`` authorization types.
    Rebinds the logging context to include the source of the token, if one is
    found.

    Parameters
    ----------
    context : `gafaelfawr.handlers.util.RequestContext`
        The context of the incoming request.
    allow_basic : `bool`, optional
        Whether to allow HTTP Basic authentication (default: `False`).

    Returns
    -------
    handle_or_token : `str` or `None`
        The handle or token if one was found, otherwise None.

    Raises
    ------
    gafaelfawr.exceptions.InvalidRequestError
        If the Authorization header is malformed.

    Notes
    -----
    A Basic Auth authentication string is normally a username and a password
    separated by colon and then base64-encoded.  Support a username of the
    token (or session handle) and a password of ``x-oauth-basic``, or a
    username of ``x-oauth-basic`` and a password of the token (or session
    handle).  If neither is the case, assume the token or session handle is
    the username.
    """
    header = context.request.headers.get("Authorization")

    # Parse the header and handle Bearer.
    if not header:
        return None
    if " " not in header:
        raise InvalidRequestError("Malformed Authorization header")
    auth_type, auth_blob = header.split(" ")
    if auth_type.lower() == "bearer":
        context.rebind_logger(token_source="bearer")
        return auth_blob

    # The only remaining permitted authentication type is (possibly) basic.
    if not allow_basic or auth_type.lower() != "basic":
        raise InvalidRequestError(f"Unknown Authorization type {auth_type}")

    # Basic, the complicated part because we are very flexible.
    try:
        basic_auth = base64.b64decode(auth_blob).decode()
        user, password = basic_auth.strip().split(":")
    except Exception as e:
        raise InvalidRequestError(f"Invalid Basic auth string: {str(e)}")
    if password == "x-oauth-basic":
        context.rebind_logger(token_source="basic-username")
        return user
    elif user == "x-oauth-basic":
        context.rebind_logger(token_source="basic-password")
        return password
    else:
        context.logger.info(
            "Neither username nor password in HTTP Basic is x-oauth-basic,"
            " assuming handle or token is username"
        )
        context.rebind_logger(token_source="basic-username")
        return user


def validate_return_url(
    context: RequestContext, return_url: Optional[str]
) -> ParseResult:
    """Validate a return URL for use in a redirect.

    Verify that the given URL is not `None` and is at the same host as the
    current route.

    Parameters
    ----------
    context : `RequestContext`
        The context of the incoming request.
    return_url : `str` or `None`
        The URL provided by the client, or `None` if none was provided.

    Returns
    -------
    parsed_return_url : `urllib.parse.ParseResult`
        The parsed return URL.

    Raises
    ------
    aiohttp.web.HTTPException
        An appropriate error if the return URL was invalid or missing.
    """
    if not return_url:
        msg = "No destination URL specified"
        context.logger.warning("Bad return URL", error=msg)
        raise web.HTTPBadRequest(reason="Bad return URL", text=msg)
    context.rebind_logger(return_url=return_url)
    parsed_return_url = urlparse(return_url)
    if parsed_return_url.hostname != context.request.url.raw_host:
        msg = f"URL is not at {context.request.host}"
        context.logger.warning("Bad return URL", error=msg)
        raise web.HTTPBadRequest(reason="Bad return URL", text=msg)
    return parsed_return_url


def verify_token(context: RequestContext, encoded_token: str) -> VerifiedToken:
    """Verify a token.

    Parameters
    ----------
    context : `RequestContext`
        The context of the incoming request.
    encoded_token : `str`
        The encoded token.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`
        The verified token.

    Raises
    ------
    gafaelfawr.exceptions.InvalidTokenError
        If the token could not be verified.
    gafaelfawr.exceptions.MissingClaimsException
        If the token is missing required claims.
    """
    token = Token(encoded=encoded_token)
    token_verifier = context.factory.create_token_verifier()
    try:
        return token_verifier.verify_internal_token(token)
    except jwt.InvalidTokenError as e:
        raise InvalidTokenError(str(e))
