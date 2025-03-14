"""Utility functions for manipulating authentication headers."""

from __future__ import annotations

import base64
import json

from fastapi import HTTPException, status

from .constants import COOKIE_NAME
from .dependencies.context import RequestContext
from .exceptions import (
    InvalidRequestError,
    InvalidTokenError,
    OAuthBearerError,
)
from .models.auth import AuthChallenge, AuthError, AuthErrorChallenge, AuthType
from .models.token import Token

__all__ = [
    "clean_authorization",
    "clean_cookies",
    "generate_challenge",
    "generate_unauthorized_challenge",
    "parse_authorization",
]


def _find_token_in_basic_auth(auth: str) -> str | None:
    """Try to find a Gafaelfawr token in a Basic ``Authorization`` header.

    Parameters
    ----------
    auth
        The HTTP Basic authorization string.

    Returns
    -------
    str or None
        The Gafaelfawr token string if found, else `None`.
    """
    try:
        basic_auth = base64.b64decode(auth).decode()
        candidates = basic_auth.strip().split(":")
    except Exception:
        return None
    for candidate in candidates:
        if Token.is_token(candidate):
            return candidate
    return None


def clean_authorization(headers: list[str]) -> list[str]:
    """Remove Gafaelfawr tokens from ``Authorization`` headers.

    Parameters
    ----------
    headers
        The ``Authorization`` headers of an incoming request, as a list
        (allowing for the case that the incoming request had multiple headers
        named ``Authorization``).

    Returns
    -------
    list of str
        Any remaining ``Authorization`` headers after removing headers
        containing Gafaelfawr tokens.

    Notes
    -----
    We don't drop all ``Authorization`` because Gafaelfawr may be doing
    stripping for anonymous routes that may be in front of services doing
    their own authentication, possibly with authentication types we don't
    recognize.
    """
    output = []
    for header in headers:
        if " " not in header:
            output.append(header)
            continue
        auth_type, auth_blob = header.split(None, 1)
        if auth_type.lower() == "bearer":
            if not Token.is_token(auth_blob):
                output.append(header)
        elif auth_type.lower() == "basic":
            if not _find_token_in_basic_auth(auth_blob):
                output.append(header)
        else:
            output.append(header)
    return output


def clean_cookies(headers: list[str]) -> list[str]:
    """Remove Gafaelfawr cookies from cookie headers.

    Parameters
    ----------
    headers
        The ``Cookie`` headers of an incoming request, as a list (allowing for
        the case that the incoming request had multiple headers named
        ``Cookie``).

    Returns
    -------
    list of str
        Any remaining ``Cookie`` headers after removing Gafaelfawr cookies.
    """
    output = []
    for header in headers:
        keep = []
        for cookie in header.split("; "):
            if "=" in cookie:
                name, _ = cookie.split("=", 1)
                if name != COOKIE_NAME:
                    keep.append(cookie)
            else:
                keep.append(cookie)
        if keep:
            output.append("; ".join(keep))
    return output


def generate_challenge(
    context: RequestContext,
    auth_type: AuthType | None,
    exc: OAuthBearerError,
    scopes: set[str] | None = None,
    *,
    error_in_headers: bool = True,
) -> HTTPException:
    """Convert an exception into an HTTP error with ``WWW-Authenticate``.

    Always return a status code of 401 or 403, even if we want to return a
    different status code to the client, but put the actual status code in
    ``X-Error-Status``. This works around limitations of the NGINX
    ``auth_request`` module, which can only handle 401 and 403 status codes.
    The status code will be retrieved from the headers and fixed by custom
    NGINX configuration in an ``error_page`` location.

    Similarly, put the actual body of the error in ``X-Error-Body`` so that it
    can be retrieved and sent to the client. Normally, NGINX discards the body
    returned by an ``auth_request`` handler.

    Parameters
    ----------
    context
        Context of the incoming request.
    auth_type
        Type of authentication to request, or `None` to not set a
        ``WWW-Authenticate`` challenge and only set the other headers.
    exc
        An exception representing a bearer token error.
    scopes
        Optional scopes to include in the challenge, primarily intended for
        `~gafaelfawr.exceptions.InsufficientScopeError` exceptions.
    error_in_headers
        Whether to put the actual error status in ``X-Error-Status`` instead
        of raising it. Disable this for OpenID Connect routes.

    Returns
    -------
    ``fastapi.HTTPException``
        A prepopulated ``fastapi.HTTPException`` object ready for raising. The
        headers will contain a ``WWW-Authenticate`` challenge.
    """
    context.logger.info(exc.message, error=str(exc))
    detail = [{"msg": str(exc), "type": exc.error}]
    headers = {"Cache-Control": "no-cache, no-store"}
    if auth_type:
        challenge = AuthErrorChallenge(
            auth_type=auth_type,
            realm=context.config.base_hostname,
            error=AuthError[exc.error],
            error_description=str(exc),
            scope=" ".join(sorted(scopes)) if scopes else None,
        )
        headers["WWW-Authenticate"] = challenge.to_header()
    if error_in_headers:
        headers["X-Error-Status"] = str(exc.status_code)
        headers["X-Error-Body"] = json.dumps({"detail": detail})
        status_code = exc.status_code if exc.status_code in (401, 403) else 403
    else:
        status_code = exc.status_code
    return HTTPException(
        headers=headers, status_code=status_code, detail=detail
    )


def generate_unauthorized_challenge(
    context: RequestContext,
    auth_type: AuthType,
    exc: InvalidTokenError | None = None,
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
    context
        The incoming request.
    auth_type
        The type of authentication to request.
    exc
        An exception representing a bearer token error.  If not present,
        assumes that no token was provided and there was no error.
    ajax_forbidden
        If set to `True`, check to see if the request was sent via AJAX (see
        Notes) and, if so, convert it to a 403 error.

    Returns
    -------
    ``fastapi.HTTPException``
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
        context.logger.warning(exc.message, error=str(exc))
        challenge: AuthChallenge = AuthErrorChallenge(
            auth_type=auth_type,
            realm=context.config.base_hostname,
            error=AuthError[exc.error],
            error_description=str(exc),
        )
        error_type = exc.error
        msg = str(exc)
    else:
        challenge = AuthChallenge(
            auth_type=auth_type, realm=context.config.base_hostname
        )
        error_type = "no_authorization"
        msg = "Authentication required"

    headers = {
        "Cache-Control": "no-cache, no-store",
        "WWW-Authenticate": challenge.to_header(),
    }

    # If the request was sent via AJAX and ajax_forbidden was set (which will
    # be true for /ingress/auth but not for the Gafaelfawr API), return 403
    # instead of 401 to avoid lots of NGINX ingress redirects.
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


def parse_authorization(
    context: RequestContext, *, only_bearer_token: bool = False
) -> str | None:
    """Find a token in the Authorization header.

    Supports either ``Bearer`` or ``Basic`` authorization types (unless
    ``only_bearer_token`` is set). Rebinds the logging context to include the
    source of the token, if one is found.

    Parameters
    ----------
    context
        The context of the incoming request.
    only_bearer_token
        If set to `True`, only accept bearer tokens.

    Returns
    -------
    str or None
        Token if one was found, otherwise `None`.

    Raises
    ------
    InvalidRequestError
        Raised if the ``Authorization`` header is malformed, if the type of
        authentication is unknown, or if ``only_bearer_token`` is `True` and
        the header used some other type of authentication.

    Notes
    -----
    A Basic Auth authentication string is normally a username and a password
    separated by colon and then base64-encoded. This method accepts a token in
    either the username or the password field.
    """
    header = context.request.headers.get("Authorization")

    # Parse the header and handle Bearer.
    if not header:
        return None
    if " " not in header:
        raise InvalidRequestError("Malformed Authorization header")
    auth_type, auth_blob = header.split(None, 1)
    if auth_type.lower() == "bearer":
        context.rebind_logger(token_source="bearer")
        return auth_blob
    elif only_bearer_token:
        raise InvalidRequestError(f"Unknown Authorization type {auth_type}")

    # The only remaining permitted authentication type is (possibly) basic.
    if auth_type.lower() != "basic":
        raise InvalidRequestError(f"Unknown Authorization type {auth_type}")

    # Basic, the complicated part because we are very flexible.  We accept the
    # token in either username or password.  If there is a token in both, we
    # use the one in username.
    try:
        basic_auth = base64.b64decode(auth_blob).decode()
        user, password = basic_auth.strip().split(":")
    except Exception as e:
        msg = f"Invalid Basic auth string: {e!s}"
        raise InvalidRequestError(msg) from e
    if Token.is_token(user):
        context.rebind_logger(token_source="basic-username")
        if Token.is_token(password) and user != password:
            msg = "Conflicting tokens in Basic username and password fields"
            raise InvalidRequestError(msg)
        return user
    elif Token.is_token(password):
        context.rebind_logger(token_source="basic-password")
        return password
    else:
        return None
