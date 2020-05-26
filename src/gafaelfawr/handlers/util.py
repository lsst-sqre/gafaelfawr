"""Utility functions for external routes."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import TYPE_CHECKING

import jwt
from aiohttp import web

from gafaelfawr.tokens import Token

if TYPE_CHECKING:
    from aioredis import Redis
    from gafaelfawr.config import Config
    from gafaelfawr.factory import ComponentFactory
    from gafaelfawr.tokens import VerifiedToken
    from structlog import BoundLogger
    from typing import Optional

__all__ = [
    "AuthChallenge",
    "AuthError",
    "AuthType",
    "InvalidTokenException",
    "RequestContext",
    "verify_token",
]


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

    factory: ComponentFactory
    """A factory for constructing Gafaelfawr components."""

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
        factory: ComponentFactory = request.config_dict["gafaelfawr/factory"]
        logger: BoundLogger = request["safir/logger"]
        redis: Redis = request.config_dict["gafaelfawr/redis"]
        return cls(
            request=request,
            config=config,
            factory=factory,
            logger=logger,
            redis=redis,
        )


class InvalidTokenException(Exception):
    """The provided token was invalid.

    This corresponds to the ``invalid_token`` error in RFC 6750: "The access
    token provided is expired, revoked, malformed, or invalid for other
    reasons.  The string form of this exception is suitable for use as the
    ``error_description`` attribute of a ``WWW-Authenticate`` header.
    """


def verify_token(context: RequestContext, encoded_token: str) -> VerifiedToken:
    """Verify a token.

    Parameters
    ----------
    context : `gafaelfawr.handlers.util.RequestContext`
        The context of the incoming request.
    encoded_token : `str`
        The encoded token.

    Returns
    -------
    token : `gafaelfawr.tokens.VerifiedToken`
        The verified token.

    Raises
    ------
    InvalidTokenException
        If the token could not be verified.
    gafaelfawr.verify.MissingClaimsException
        If the token is missing required claims.
    """
    token = Token(encoded=encoded_token)
    token_verifier = context.factory.create_token_verifier(
        context.request, context.logger
    )
    try:
        return token_verifier.verify_internal_token(token)
    except jwt.InvalidTokenError as e:
        raise InvalidTokenException(str(e))
