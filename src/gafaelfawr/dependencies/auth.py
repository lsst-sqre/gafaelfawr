"""Authentication dependencies for FastAPI."""

from typing import Optional
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

__all__ = ["Authenticate"]


class Authenticate:
    """Dependency to verify user authentication.

    This is a class so that multiple authentication policies can be
    constructed while easily sharing the same code.

    Parameters
    ----------
    require_session : `bool`, optional
        Require that the credentials come from a cookie, not an
        ``Authorization`` header.  The default is `False`.
    require_scope : `str`, optional
        If set, access will be denied if the authentication token does not
        have this scope.
    redirect_if_unauthenticated : `bool`, optional
        If the request is unauthenticated, redirect it to the ``/login`` route
        rather than returning a challenge.  The default is `False`.
    allow_bootstrap_token : `bool`, optional
        Allow use of the bootstrap token to authenticate to this route.  The
        default is `False`.
    auth_type : `gafaelfawr.auth.AuthType`
        The type of the challenge if the user is not authenticated.  The
        default is `gafaelfawr.auth.AuthType.Bearer`.
    ajax_forbidden : `bool`, optional
        If set to `True`, check to see if the request was sent via AJAX (see
        Notes) and, if so, convert it to a 403 error.  The default is `False`.
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

    async def __call__(
        self, context: RequestContext = Depends(context_dependency)
    ) -> TokenData:
        """Authenticate the request.

        For requests authenticated via session cookie, also checks that a CSRF
        token was provided in the ``X-CSRF-Token`` header if the request is
        anything other than GET or OPTIONS.

        Always check the user's cookie-based session first before checking the
        ``Authorization`` header because some applications (JupyterHub, for
        instance) may use the ``Authorization`` header for their own purposes.

        Parameters
        ----------
        context : `gafaelfawr.dependencies.context.RequestContext`
            The request context.

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
        elif not self.require_session:
            try:
                token_str = parse_authorization(context)
                if token_str:
                    token = Token.from_str(token_str)
            except (InvalidRequestError, InvalidTokenError) as e:
                raise generate_challenge(context, self.auth_type, e)
        if not token:
            if self.redirect_if_unauthenticated:
                raise self._redirect_to_login(context)
            else:
                raise generate_unauthorized_challenge(
                    context, self.auth_type, ajax_forbidden=self.ajax_forbidden
                )

        token_service = context.factory.create_token_service()
        data = await token_service.get_data(token)
        if not data:
            if context.state.token:
                if self.redirect_if_unauthenticated:
                    raise self._redirect_to_login(context)
                else:
                    raise generate_unauthorized_challenge(
                        context,
                        self.auth_type,
                        ajax_forbidden=self.ajax_forbidden,
                    )
            else:
                exc = InvalidTokenError("Token is not valid")
                raise generate_challenge(context, self.auth_type, exc)

        context.rebind_logger(
            token=token.key,
            user=data.username,
            scope=" ".join(sorted(data.scopes)),
        )

        if self.require_scope and self.require_scope not in data.scopes:
            msg = f"Token does not have required scope {self.require_scope}"
            context.logger.info("Permission denied", error=msg)
            raise PermissionDeniedError(msg)

        return data

    def _redirect_to_login(self, context: RequestContext) -> HTTPException:
        """Redirect to the ``/login`` route.

        Send a return URL pointing to the current page.

        Returns
        -------
        exc : `fastapi.HTTPException`
            The redirect.
        """
        query = urlencode({"rd": str(context.request.url)})
        login_url = urlparse("/login")._replace(query=query).geturl()
        context.logger.info("Redirecting user for authentication")
        return HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": login_url},
        )
