"""Handler for the user information route (``/auth/userinfo``)."""

from __future__ import annotations

from typing import Any, Mapping

from fastapi import APIRouter, Depends

from gafaelfawr.auth import (
    AuthType,
    generate_challenge,
    generate_unauthorized_challenge,
    parse_authorization,
)
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import InvalidRequestError, InvalidTokenError
from gafaelfawr.models.oidc import OIDCToken, OIDCVerifiedToken

router = APIRouter()

__all__ = ["get_userinfo"]


def verified_token(
    context: RequestContext = Depends(context_dependency),
) -> OIDCVerifiedToken:
    """Require that a request be authenticated with a token.

    The token must be present in either an ``Authorization`` header or in the
    ``X-Auth-Request-Token`` header added by NGINX when configured to use
    Gafaelfawr as an ``auth_request`` handler.

    Raises
    ------
    fastapi.HTTPException
        An authorization challenge if no token is provided.
    """
    try:
        encoded_token = parse_authorization(context)
    except InvalidRequestError as e:
        raise generate_challenge(context, AuthType.Bearer, e)
    if not encoded_token:
        raise generate_unauthorized_challenge(context, AuthType.Bearer)
    try:
        unverified_token = OIDCToken(encoded=encoded_token)
        token_verifier = context.factory.create_token_verifier()
        token = token_verifier.verify_internal_token(unverified_token)
    except InvalidTokenError as e:
        raise generate_challenge(context, AuthType.Bearer, e)

    # Add user information to the logger.
    context.rebind_logger(token=token.jti, user=token.username)

    return token


@router.get("/auth/userinfo")
async def get_userinfo(
    token: OIDCVerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context_dependency),
) -> Mapping[str, Any]:
    """Return information about the holder of a JWT."""
    context.logger.info("Returned user information")
    return token.claims
