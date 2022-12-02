"""Authentication dependencies for FastAPI."""

from typing import Optional
from urllib.parse import urlencode, urlparse

from fastapi import Depends, Header, HTTPException, status

from ..auth import (
    generate_challenge,
    generate_unauthorized_challenge,
    parse_authorization,
)
from ..exceptions import (
    InvalidCSRFError,
    InvalidRequestError,
    InvalidTokenError,
    PermissionDeniedError,
)
from ..models.auth import AuthType
from ..models.oidc import OIDCToken, OIDCVerifiedToken
from ..models.token import Token, TokenData
from .context import RequestContext, context_dependency

__all__ = [
    "Authenticate",
    "AuthenticateRead",
    "AuthenticateWrite",
    "verified_oidc_token",
]


class Authenticate:
    """Dependency to verify user authentication.

    This is a class so that multiple authentication policies can be
    constructed while easily sharing the same code.  It is used as a base
    class for `AuthenticateRead` and `AuthenticateWrite`, which provide
    ``__call__`` implementations that do the work.

    Parameters
    ----------
    require_session
        Require that the credentials come from a cookie, not an
        ``Authorization`` header.
    require_scope
        If set, access will be denied if the authentication token does not
        have this scope.
    redirect_if_unauthenticated
        If the request is unauthenticated, redirect it to the ``/login`` route
        rather than returning a challenge.
    allow_bootstrap_token
        Allow use of the bootstrap token to authenticate to this route.
    auth_type
        The type of the challenge if the user is not authenticated.
    ajax_forbidden
        If set to `True`, check to see if the request was sent via AJAX (see
        Notes) and, if so, convert it to a 403 error.
    """

    def __init__(
        self,
        require_session: bool = False,
        require_scope: Optional[str] = None,
        redirect_if_unauthenticated: bool = False,
        allow_bootstrap_token: bool = False,
        auth_type: AuthType = AuthType.Bearer,
        ajax_forbidden: bool = False,
    ) -> None:
        self.require_session = require_session
        self.require_scope = require_scope
        self.redirect_if_unauthenticated = redirect_if_unauthenticated
        self.allow_bootstrap_token = allow_bootstrap_token
        self.auth_type = auth_type
        self.ajax_forbidden = ajax_forbidden

    async def authenticate(
        self, context: RequestContext, x_csrf_token: Optional[str] = None
    ) -> TokenData:
        """Authenticate the request.

        Always check the user's cookie-based session first before checking the
        ``Authorization`` header because some applications (JupyterHub, for
        instance) may use the ``Authorization`` header for their own purposes.

        If the request was authenticated via a browser cookie rather than a
        provided ``Authorization`` header, and the method was something other
        than ``GET`` or ``OPTIONS``, require and verify the CSRF header as
        well.

        Parameters
        ----------
        context
            The request context.
        x_csrf_token
            The value of the ``X-CSRF-Token`` header, if provided.

        Returns
        -------
        TokenData
            The data associated with the verified token.

        Raises
        ------
        fastapi.HTTPException
            Raised if authentication is not provided or is not valid.
        """
        token = context.state.token
        if token:
            context.rebind_logger(token_source="cookie")
            self._verify_csrf(context, x_csrf_token)
        elif not self.require_session:
            try:
                token_str = parse_authorization(context)
                if token_str:
                    token = Token.from_str(token_str)
            except (InvalidRequestError, InvalidTokenError) as e:
                raise generate_challenge(context, self.auth_type, e)
        if not token:
            raise self._redirect_or_error(context)

        if self.allow_bootstrap_token:
            if token == context.config.bootstrap_token:
                bootstrap_data = TokenData.bootstrap_token()
                context.rebind_logger(
                    token="<bootstrap>",
                    user="<bootstrap>",
                    scopes=sorted(bootstrap_data.scopes),
                )
                context.logger.info("Authenticated with bootstrap token")
                return bootstrap_data

        token_service = context.factory.create_token_service()
        data = await token_service.get_data(token)
        if not data:
            if context.state.token:
                raise self._redirect_or_error(context)
            else:
                exc = InvalidTokenError("Token is not valid")
                raise generate_challenge(context, self.auth_type, exc)

        context.rebind_logger(
            token=token.key,
            user=data.username,
            scopes=sorted(data.scopes),
        )

        if self.require_scope and self.require_scope not in data.scopes:
            msg = f"Token does not have required scope {self.require_scope}"
            context.logger.info("Permission denied", error=msg)
            raise PermissionDeniedError(msg)

        return data

    def _redirect_or_error(self, context: RequestContext) -> HTTPException:
        """Redirect to the ``/login`` route or return a 401 error.

        If ``redirect_if_unauthenticated`` is set, send a return URL pointing
        to the current page.  Otherwise, return a suitable 401 error.

        Returns
        -------
        exc
            The redirect.
        """
        if not self.redirect_if_unauthenticated:
            return generate_unauthorized_challenge(
                context, self.auth_type, ajax_forbidden=self.ajax_forbidden
            )
        query = urlencode({"rd": str(context.request.url)})
        login_url = urlparse("/login")._replace(query=query).geturl()
        context.logger.info("Redirecting user for authentication")
        return HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": login_url},
        )

    def _verify_csrf(
        self, context: RequestContext, x_csrf_token: str | None
    ) -> None:
        """Check the provided CSRF token is correct.

        Raises
        ------
        fastapi.HTTPException
            Raised if no CSRF token was provided or if it was incorrect, and
            the method was something other than GET or OPTIONS.
        """
        if context.request.method in ("GET", "OPTIONS"):
            return
        error = None
        if not x_csrf_token:
            error = "CSRF token required in X-CSRF-Token header"
        if x_csrf_token != context.state.csrf:
            error = "Invalid CSRF token"
        if error:
            context.logger.error("CSRF verification failed", error=error)
            raise InvalidCSRFError(error)


class AuthenticateRead(Authenticate):
    """Authenticate a read API.

    Should be used as a FastAPI dependency.
    """

    async def __call__(
        self, context: RequestContext = Depends(context_dependency)
    ) -> TokenData:
        return await self.authenticate(context)


class AuthenticateWrite(Authenticate):
    """Authenticate a write API.

    Should be used as a FastAPI dependency.
    """

    async def __call__(
        self,
        x_csrf_token: Optional[str] = Header(
            None,
            title="CSRF token",
            description=(
                "Only required when authenticating with a cookie, such as via"
                " the JavaScript UI."
            ),
            example="OmNdVTtKKuK_VuJsGFdrqg",
        ),
        context: RequestContext = Depends(context_dependency),
    ) -> TokenData:
        return await self.authenticate(context, x_csrf_token)


async def verified_oidc_token(
    context: RequestContext = Depends(context_dependency),
) -> OIDCVerifiedToken:
    """Require that a request be authenticated with an OpenID Connect token.

    Raises
    ------
    fastapi.HTTPException
        Raised if no token is provided or if the token is not valid. Contains
        an authorization challenge.
    """
    try:
        encoded_token = parse_authorization(context)
    except InvalidRequestError as e:
        raise generate_challenge(context, AuthType.Bearer, e)
    if not encoded_token:
        raise generate_unauthorized_challenge(context, AuthType.Bearer)
    unverified_token = OIDCToken(encoded=encoded_token)
    oidc_service = context.factory.create_oidc_service()
    try:
        token = oidc_service.verify_token(unverified_token)
    except InvalidTokenError as e:
        raise generate_challenge(context, AuthType.Bearer, e)

    # Add user information to the logger.
    context.rebind_logger(token=token.jti, user=token.claims["sub"])

    return token
