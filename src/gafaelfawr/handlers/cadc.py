"""Handlers for CADC authentication integration (``/auth/cadc``).

Hopefully this can eventually be integrated with the OpenID Connect handlers
by allowing the ``/auth/openid/userinfo`` endpoint to take either an OpenID
Connect token or a Gafaelfawr token and return JWT-compatible claims, but
currently CADC code requires ``sub`` be a UUID and we have other integrations
that use ``sub`` as a username.
"""

from typing import Annotated

from fastapi import APIRouter, Depends
from safir.models import ErrorModel
from safir.slack.webhook import SlackRouteErrorHandler

from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..models.token import TokenData
from ..models.userinfo import CADCUserInfo

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
    response_model_exclude_none=True,
    responses={
        401: {"description": "Unauthenticated"},
        403: {"description": "Permission denied", "model": ErrorModel},
    },
    summary="Get CADC-compatible user metadata",
    tags=["oidc"],
)
async def get_userinfo(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> CADCUserInfo:
    return CADCUserInfo(
        exp=auth_data.expires,
        preferred_username=auth_data.username,
        sub=auth_data.username,
    )
