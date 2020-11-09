"""Authentication dependencies for FastAPI."""

from urllib.parse import urlencode, urlparse

from fastapi import Depends, HTTPException, status

from gafaelfawr.auth import (
    AuthType,
    generate_challenge,
    generate_unauthorized_challenge,
    parse_authorization,
)
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import (
    InvalidRequestError,
    InvalidTokenError,
    PermissionDeniedError,
)
from gafaelfawr.models.token import Token, TokenData

__all__ = ["authenticate", "authenticate_session", "authenticate_with_type"]


async def _authenticate_helper(
    context: RequestContext, auth_type: AuthType
) -> TokenData:
    """Helper function for authenticate and authenticate_with_type.

    Check that the request is authenticated.  For requests authenticated via
    session cookie, also checks that a CSRF token was provided in the
    ``X-CSRF-Token`` header if the request is anything other than GET or
    OPTIONS.

    Always check the user's cookie-based session first before checking the
    ``Authorization`` header because some applications (JupyterHub, for
    instance) may use the ``Authorization`` header for their own purposes.

    Returns
    -------
    data : `gafaelfawr.models.token.TokenData`
        The data associated with the verified token.

    Raises
    ------
    fastapi.HTTPException
        If authentication is not provided or is not valid.
    """
    token = context.state.token
    if token:
        context.rebind_logger(token_source="cookie")
    else:
        try:
            token_str = parse_authorization(context)
            if token_str:
                token = Token.from_str(token_str)
        except (InvalidRequestError, InvalidTokenError) as e:
            raise generate_challenge(context, auth_type, e)
    if not token:
        raise generate_unauthorized_challenge(context, auth_type)

    token_manager = context.factory.create_token_manager()
    data = await token_manager.get_data(token)
    if not data:
        exc = InvalidTokenError("Token is not valid")
        raise generate_challenge(context, auth_type, exc)

    context.rebind_logger(
        token=token.key,
        user=data.username,
        scope=" ".join(sorted(data.scopes)),
    )
    return data


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
    return await _authenticate_helper(context, AuthType.Bearer)


async def authenticate_with_type(
    auth_type: AuthType = AuthType.Bearer,
    context: RequestContext = Depends(context_dependency),
) -> TokenData:
    """Check that the request is authenticated with configurable challenge.

    Same as :py:func:`authenticate` except that the type of the challenge can
    be specified with the ``auth_type`` request parameter.

    Returns
    -------
    data : `gafaelfawr.models.token.TokenData`
        The data associated with the verified token.

    Raises
    ------
    fastapi.HTTPException
        If authentication is not provided or is not valid.
    """
    return await _authenticate_helper(context, auth_type)


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


async def require_admin(
    token_data: TokenData = Depends(authenticate),
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
    if not admin_manager.is_admin(token_data.username):
        raise PermissionDeniedError(f"{token_data.username} is not an admin")
    return token_data.username
