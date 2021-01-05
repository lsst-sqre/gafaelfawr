"""Authentication dependencies for route handlers."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional, Set

from fastapi import HTTPException, status

from gafaelfawr.dependencies.context import RequestContext
from gafaelfawr.exceptions import (
    InvalidRequestError,
    InvalidTokenError,
    OAuthBearerError,
)

__all__ = [
    "AuthType",
    "AuthChallenge",
    "AuthError",
    "AuthErrorChallenge",
    "generate_challenge",
    "generate_unauthorized_challenge",
    "parse_authorization",
]


class AuthType(str, Enum):
    """Authentication types for the WWW-Authenticate header."""

    Basic = "basic"
    Bearer = "bearer"


class AuthError(Enum):
    """Valid authentication errors for a WWW-Authenticate header.

    Defined in RFC 6750.
    """

    invalid_request = auto()
    invalid_token = auto()
    insufficient_scope = auto()


@dataclass
class AuthChallenge:
    """Represents a ``WWW-Authenticate`` header for a simple challenge."""

    auth_type: AuthType
    """The authentication type (the first part of the header)."""

    realm: str
    """The value of the realm attribute."""

    def as_header(self) -> str:
        """Construct the WWW-Authenticate header for this challenge.

        Returns
        -------
        header : `str`
            Contents of the WWW-Authenticate header.
        """
        return f'{self.auth_type.name} realm="{self.realm}"'


@dataclass
class AuthErrorChallenge(AuthChallenge):
    """Represents a ``WWW-Authenticate`` header for an error challenge."""

    error: AuthError
    """The value of the error attribute if present."""

    error_description: str
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
        if self.auth_type == AuthType.Basic:
            # Basic doesn't support error information.
            return f'{self.auth_type.name} realm="{self.realm}"'

        # Strip invalid characters from the description.
        error_description = re.sub(r'["\\]', "", self.error_description)

        info = f'realm="{self.realm}", error="{self.error.name}"'
        info += f', error_description="{error_description}"'
        if self.scope:
            info += f', scope="{self.scope}"'
        return f"{self.auth_type.name} {info}"


def generate_challenge(
    context: RequestContext,
    auth_type: AuthType,
    exc: OAuthBearerError,
    scopes: Optional[Set[str]] = None,
) -> HTTPException:
    """Convert an exception into an HTTP error with ``WWW-Authenticate``.

    Parameters
    ----------
    request : `gafaelfawr.dependencies.context.RequestContext`
        The context of the incoming request.
    auth_type : `AuthType`
        The type of authentication to request.
    exc : `gafaelfawr.exceptions.OAuthBearerError`
        An exception representing a bearer token error.
    scopes : Set[`str`], optional
        Optional scopes to include in the challenge, primarily intended for
        `~gafaelfawr.exceptions.InsufficientScopeError` exceptions.

    Returns
    -------
    fastapi.HTTPException
        A prepopulated `fastapi.HTTPException` object ready for raising.  The
        headers will contain a ``WWW-Authenticate`` challenge.
    """
    context.logger.warning("%s", exc.message, error=str(exc))
    challenge = AuthErrorChallenge(
        auth_type=auth_type,
        realm=context.config.realm,
        error=AuthError[exc.error],
        error_description=str(exc),
        scope=" ".join(sorted(scopes)) if scopes else None,
    )
    headers = {
        "Cache-Control": "no-cache, must-revalidate",
        "WWW-Authenticate": challenge.as_header(),
    }
    return HTTPException(
        headers=headers,
        status_code=exc.status_code,
        detail={"msg": str(exc), "type": exc.error},
    )


def generate_unauthorized_challenge(
    context: RequestContext,
    auth_type: AuthType,
    exc: Optional[InvalidTokenError] = None,
    *,
    ajax_forbidden: bool = False,
) -> HTTPException:
    """Construct exception for a 401 response with AJAX handling.

    This is a special case of :py:func:`generate_challenge` for generating 401
    Unauthorized challenges.  For these, the exception is optional, since
    there is no error and thus no ``error_description`` field if the token was
    simply not present.

    Parameters
    ----------
    context : `gafaelfawr.dependencies.context.RequestContext`
        The incoming request.
    auth_type : `AuthType`
        The type of authentication to request.
    exc : `gafaelfawr.exceptions.OAuthBearerError`, optional
        An exception representing a bearer token error.  If not present,
        assumes that no token was provided and there was no error.
    ajax_forbidden : `bool`, optional
        If set to `True`, check to see if the request was sent via AJAX (see
        Notes) and, if so, convert it to a 403 error.  The default is `False`.

    Returns
    -------
    exception : `fastapi.HTTPException`
        The exception to raise, either a 403 (for AJAX) or a 401.

    Notes
    -----
    If the request contains ``X-Requested-With: XMLHttpRequest``, return 403
    rather than 401.  The presence of this header indicates an AJAX request,
    which in turn means that the request is not under full control of the
    browser window.  The redirect ingress-nginx will send will therefore not
    result in the user going to the authentication provider properly, but may
    result in a spurious request from background AJAX that cannot be
    completed.  That, in turn, can cause unnecessary load on the
    authentication provider and may result in rate limiting.

    Checking for this header does not catch all requests that are pointless to
    redirect (image and CSS requests, for instance), and not all AJAX requests
    will send the header, but every request with this header should be
    pointless to redirect, so at least it cuts down on the noise.
    This corresponds to the ``invalid_token`` error in RFC 6750: "The access
    token provided is expired, revoked, malformed, or invalid for other
    reasons.  The string form of this exception is suitable for use as the
    ``error_description`` attribute of a ``WWW-Authenticate`` header.
    """
    if exc:
        context.logger.warning("%s", exc.message, error=str(exc))
        challenge: AuthChallenge = AuthErrorChallenge(
            auth_type=auth_type,
            realm=context.config.realm,
            error=AuthError[exc.error],
            error_description=str(exc),
        )
        error_type = exc.error
        msg = str(exc)
    else:
        context.logger.info("No token found, returning unauthorized")
        challenge = AuthChallenge(
            auth_type=auth_type, realm=context.config.realm
        )
        error_type = "no_authorization"
        msg = "Authentication required"

    headers = {
        "Cache-Control": "no-cache, must-revalidate",
        "WWW-Authenticate": challenge.as_header(),
    }

    # If the request was sent via AJAX and ajax_forbidden was set (which will
    # be true for /auth but not for the Gafaelfawr API), return 403 instead of
    # 401 to avoid lots of NGINX ingress redirects.
    status_code = status.HTTP_401_UNAUTHORIZED
    if ajax_forbidden:
        requested_with = context.request.headers.get("X-Requested-With")
        if requested_with and requested_with.lower() == "xmlhttprequest":
            status_code = status.HTTP_403_FORBIDDEN

    return HTTPException(
        headers=headers,
        status_code=status_code,
        detail={"msg": msg, "type": error_type},
    )


def parse_authorization(context: RequestContext) -> Optional[str]:
    """Find a handle or token in the Authorization header.

    Supports either ``Bearer`` or ``Basic`` authorization types.  Rebinds the
    logging context to include the source of the token, if one is found.

    Parameters
    ----------
    context : `gafaelfawr.dependencies.context.RequestContext`
        The context of the incoming request.

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
    if auth_type.lower() != "basic":
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
