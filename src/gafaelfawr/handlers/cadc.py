"""Handlers for CADC authentication integration (``/auth/cadc``).

Hopefully this can eventually be integrated with the OpenID Connect handlers
by allowing the ``/auth/openid/userinfo`` endpoint to take either an OpenID
Connect token or a Gafaelfawr token and return JWT-compatible claims, but
currently CADC code requires ``sub`` be a UUID and we have other integrations
that use ``sub`` as a username.
"""

from uuid import uuid5

from fastapi import APIRouter, Depends, HTTPException, status
from safir.models import ErrorModel
from safir.slack.webhook import SlackRouteErrorHandler

from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import (
    ExternalUserInfoError,
    NotConfiguredError,
    PermissionDeniedError,
)
from ..models.token import CADCUserInfo, TokenData

__all__ = ["router"]

router = APIRouter(
    responses={
        404: {
            "description": "CADC integration not configured",
            "model": ErrorModel,
        },
    },
    route_class=SlackRouteErrorHandler,
)
authenticate_read = AuthenticateRead()


@router.get(
    "/auth/cadc/userinfo",
    description=(
        "Return metadata about the authenticated user in a format similar to"
        " that of OpenID Connect JWT claims and meeting the specific"
        " requirements of CADC's authentication code. This API is expected to"
        " be temporary and to be merged into a different route in a future"
        " version."
    ),
    response_model=CADCUserInfo,
    response_model_exclude_none=True,
    responses={
        401: {"description": "Unauthenticated"},
        403: {"description": "Permission denied", "model": ErrorModel},
    },
    summary="Get CADC-compatible user metadata",
    tags=["oidc"],
)
async def get_userinfo(
    auth_data: TokenData = Depends(authenticate_read),
    context: RequestContext = Depends(context_dependency),
) -> CADCUserInfo:
    config = context.config
    if not config.cadc_base_uuid:
        msg = "CADC-compatible authentication not configured"
        raise NotConfiguredError(msg)
    user_info_service = context.factory.create_user_info_service()
    try:
        user_info = await user_info_service.get_user_info_from_token(auth_data)
    except ExternalUserInfoError as e:
        msg = "Unable to get user information"
        context.logger.exception(msg, error=str(e))
        slack_client = context.factory.create_slack_client()
        if slack_client:
            await slack_client.post_exception(e)
        raise HTTPException(
            headers={"Cache-Control": "no-cache, no-store"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=[{"msg": msg, "type": "user_info_failed"}],
        ) from e
    if not user_info.uid:
        error = "User has no UID"
        context.logger.warning("Cannot generate CADC auth data", error=error)
        raise PermissionDeniedError(error)
    return CADCUserInfo(
        exp=auth_data.expires,
        preferred_username=auth_data.username,
        sub=uuid5(config.cadc_base_uuid, str(user_info.uid)),
    )
