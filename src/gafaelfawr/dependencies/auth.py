"""Authentication dependencies for FastAPI."""

from typing import Optional
from urllib.parse import urlencode, urlparse

from fastapi import Depends, Header, HTTPException, Request, status

from gafaelfawr.auth import (
    AuthType,
    generate_challenge,
    generate_unauthorized_challenge,
    parse_authorization,
    verify_token,
)
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import (
    InvalidRequestError,
    InvalidTokenError,
    PermissionDeniedError,
)
from gafaelfawr.models.token import Token, TokenData
from gafaelfawr.session import Session
from gafaelfawr.tokens import VerifiedToken

__all__ = [
    "authenticate",
    "authenticate_session",
    "verified_session",
    "verified_token",
]


async def verified_session(
    request: Request,
    context: RequestContext = Depends(context_dependency),
) -> Session:
    """Require that a request be authenticated with a session cookie.

    Extract the token from the session cookie, verify it, and pass the
    underlying session into the handler that declares this dependency.

    Raises
    ------
    fastapi.HTTPException
        Redirect to ``/login`` if the user is not currently authenticated.
    """
    session = None
    if request.state.cookie.handle:
        session_store = context.factory.create_session_store()
        session = await session_store.get_session(request.state.cookie.handle)

    # If there is no active session, redirect to /login.
    if not session:
        query = urlencode({"rd": str(context.request.url)})
        login_url = urlparse("/login")._replace(query=query).geturl()
        context.logger.info("Redirecting user for authentication")
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": login_url},
        )

    # On success, add some context to the logger.
    context.rebind_logger(
        token=session.token.jti,
        user=session.token.username,
        scope=" ".join(sorted(session.token.scope)),
        token_source="cookie",
    )

    return session


def verified_token(
    x_auth_request_token: Optional[str] = Header(None),
    context: RequestContext = Depends(context_dependency),
) -> VerifiedToken:
    """Require that a request be authenticated with a token.

    The token must be present in either an ``Authorization`` header or in the
    ``X-Auth-Request-Token`` header added by NGINX when configured to use
    Gafaelfawr as an ``auth_request`` handler.

    Raises
    ------
    fastapi.HTTPException
        An authorization challenge if no token is provided.
    """
    unverified_token = x_auth_request_token
    if not unverified_token:
        try:
            unverified_token = parse_authorization(context)
        except InvalidRequestError as e:
            raise generate_challenge(context, AuthType.Bearer, e)
    if not unverified_token:
        raise generate_unauthorized_challenge(context, AuthType.Bearer)
    try:
        token = verify_token(context, unverified_token)
    except InvalidTokenError as e:
        raise generate_challenge(context, AuthType.Bearer, e)

    # Add user information to the logger.
    context.rebind_logger(
        token=token.jti,
        user=token.username,
        scope=" ".join(sorted(token.scope)),
    )

    return token


async def require_admin(
    token: VerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context_dependency),
) -> str:
    """Require the request be from a token administrator.

    Returns
    -------
    username : `str`
        The username of the authenticated user.

    Raises
    ------
    gafaelfawr.exceptions.PermissionDeniedError
        If the request is not from an administrator.
    """
    admin_manager = context.factory.create_admin_manager()
    if not admin_manager.is_admin(token.username):
        raise PermissionDeniedError(f"{token.username} is not an admin")
    return token.username


async def authenticate(
    context: RequestContext = Depends(context_dependency),
) -> TokenData:
    """Check that the request is authenticated.

    For requests authenticated via session cookie, also checks that a CSRF
    token was provided in the ``X-CSRF-Token`` header if the request is
    anything other than GET or OPTIONS.

    Returns
    -------
    data : `gafaelfawr.models.token.TokenData`
        The data associated with the verified token.

    Raises
    ------
    fastapi.HTTPException
        If authentication is not provided or is not valid.
    """
    token = None
    try:
        token_str = parse_authorization(context)
        if token_str:
            token = Token.from_str(token_str)
    except (InvalidRequestError, InvalidTokenError) as e:
        raise generate_challenge(context, AuthType.Bearer, e)
    if not token and context.state.token:
        token = context.state.token
        context.rebind_logger(token_source="cookie")
    if not token:
        raise generate_unauthorized_challenge(context, AuthType.Bearer)

    token_manager = context.factory.create_token_manager()
    data = await token_manager.get_data(token)
    if not data:
        exc = InvalidTokenError("Token is not valid")
        raise generate_challenge(context, AuthType.Bearer, exc)

    context.rebind_logger(
        token=token.key,
        user=data.username,
        scope=" ".join(sorted(data.scopes)),
    )
    return data


async def authenticate_session(
    context: RequestContext = Depends(context_dependency),
) -> TokenData:
    """Check cookie authentication and, if not found, redirect to ``/login``.

    Returns
    -------
    data : `gafaelfawr.models.token.TokenData`
        The data associated with the verified token.

    Raises
    ------
    fastapi.HTTPException
        If authentication is not provided or is not valid.
    """
    data = None
    if context.state.token:
        token_manager = context.factory.create_token_manager()
        data = await token_manager.get_data(context.state.token)

    # If there is no active session, redirect to /login.
    if not data:
        query = urlencode({"rd": str(context.request.url)})
        login_url = urlparse("/login")._replace(query=query).geturl()
        context.logger.info("Redirecting user for authentication")
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": login_url},
        )

    context.rebind_logger(
        token=data.token.key,
        user=data.username,
        scope=" ".join(sorted(data.scopes)),
        token_source="cookie",
    )
    return data
