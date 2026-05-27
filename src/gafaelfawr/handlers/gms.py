"""Route handlers for the IVOA GMS protocol."""

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from fastapi.responses import PlainTextResponse
from safir.sentry import report_exception
from safir.slack.webhook import SlackRouteErrorHandler

from ..constants import LDAP_CACHE_LIFETIME
from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import ExternalUserInfoError
from ..models.token import TokenData

router = APIRouter(route_class=SlackRouteErrorHandler)
"""Router for GMS routes."""

__all__ = ["router"]


@router.get(
    "/auth/gms",
    description=(
        "Get group information in IVOA GMS format for the authenticated user"
    ),
    response_class=PlainTextResponse,
    responses={401: {"description": "Unauthenticated"}},
    summary="Get user groups",
    tags=["user"],
)
async def get_gms(
    group: Annotated[list[str] | None, Query()] = None,
    *,
    response: Response,
    auth_data: Annotated[TokenData, Depends(AuthenticateRead())],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> str:
    wanted = set(group) if group else None

    # Get the user information.
    user_info_service = context.factory.create_user_info_service()
    try:
        user_info = await user_info_service.get_user_info_from_token(auth_data)
    except ExternalUserInfoError as e:
        msg = "Unable to get user information"
        context.logger.exception(msg, error=str(e))
        slack_client = context.factory.create_slack_client()
        await report_exception(e, slack_client=slack_client)
        raise HTTPException(
            headers={"Cache-Control": "no-cache, no-store"},
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=[{"msg": msg, "type": "user_info_failed"}],
        ) from e

    # Set the Expires header on the response to reflect our caching interval
    # for groups. Use the LDAP cache lifetime unconditionally, even if
    # configured to use GitHub, for simplicity. The worst consequence would be
    # some additional client requests, and this handler should be very fast.
    expires = datetime.now(tz=UTC) + timedelta(seconds=LDAP_CACHE_LIFETIME)
    response.headers["Expires"] = format_datetime(expires, usegmt=True)

    # Construct the response. If no groups are provided, list all of the
    # user's groups. If groups are provided, only list the intersection
    # between that list of groups and the user's groups. Each group line must
    # end with a newline, but if there are no matching groups, the body must
    # be completely empty.
    seen = {g.name for g in user_info.groups}
    matching = seen & wanted if wanted else seen
    if matching:
        return "\r\n".join(sorted(matching)) + "\r\n"
    else:
        return ""
