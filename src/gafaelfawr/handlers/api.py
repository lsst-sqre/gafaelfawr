"""Route handlers for the token API.

All the route handlers are intentionally defined in a single file to encourage
the implementation to be very short. All the business logic should be defined
in manager objects and the output formatting should be handled by response
models.
"""

from typing import Annotated, Any
from urllib.parse import quote

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Response,
    status,
)
from safir.models import ErrorLocation, ErrorModel
from safir.pydantic import UtcDatetime
from safir.slack.webhook import SlackRouteErrorHandler

from ..constants import ACTOR_REGEX, CURSOR_REGEX, USERNAME_REGEX
from ..dependencies.auth import AuthenticateRead, AuthenticateWrite
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import ExternalUserInfoError, NotFoundError
from ..models.admin import Admin
from ..models.auth import APIConfig, APILoginResponse, Scope
from ..models.enums import TokenType
from ..models.history import TokenChangeHistoryCursor, TokenChangeHistoryEntry
from ..models.quota import QuotaConfig
from ..models.token import (
    AdminTokenRequest,
    NewToken,
    TokenData,
    TokenInfo,
    UserTokenModifyRequest,
    UserTokenRequest,
)
from ..models.userinfo import UserInfo
from ..util import random_128_bits

router = APIRouter(route_class=SlackRouteErrorHandler)
"""Router for API routes."""

__all__ = ["router"]

authenticate_read = AuthenticateRead()
authenticate_write = AuthenticateWrite()
authenticate_admin_read = AuthenticateRead(
    require_scope="admin:token", allow_bootstrap_token=True
)
authenticate_admin_write = AuthenticateWrite(
    require_scope="admin:token", allow_bootstrap_token=True
)
authenticate_session_read = AuthenticateRead(require_session=True)

_pagination_headers = {
    "Link": {
        "description": (
            "Links to paginated results if `limit` or `cursor` was given,"
            " structured according to"
            " [RFC 5988](https://datatracker.ietf.org/doc/html/rfc5988)."
            " One or more of `prev`, `next`, and `first` relation types"
            " may be provided."
        ),
        "schema": {"type": "string"},
    },
    "X-Total-Count": {
        "description": (
            "Total number of results if `limit` or `cursor` was given"
        ),
        "schema": {"type": "integer"},
    },
}


@router.get(
    "/auth/api/v1/admins",
    dependencies=[Depends(authenticate_admin_read)],
    summary="List all administrators",
    tags=["admin"],
)
async def get_admins(
    *,
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> list[Admin]:
    admin_service = context.factory.create_admin_service()
    return await admin_service.get_admins()


@router.post(
    "/auth/api/v1/admins",
    status_code=204,
    summary="Add new administrator",
    tags=["admin"],
)
async def add_admin(
    *,
    admin: Admin,
    auth_data: Annotated[TokenData, Depends(authenticate_admin_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> None:
    admin_service = context.factory.create_admin_service()
    await admin_service.add_admin(
        admin.username,
        actor=auth_data.username,
        ip_address=context.ip_address,
    )


@router.delete(
    "/auth/api/v1/admins/{username}",
    responses={
        403: {"description": "Permission denied", "model": ErrorModel},
        404: {"description": "Specified user is not an administrator"},
    },
    status_code=204,
    summary="Delete an administrator",
    tags=["admin"],
)
async def delete_admin(
    *,
    username: Annotated[
        str,
        Path(
            title="Administrator",
            description="Username of administrator to delete",
            examples=["adminuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    auth_data: Annotated[TokenData, Depends(authenticate_admin_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> None:
    admin_service = context.factory.create_admin_service()
    success = await admin_service.delete_admin(
        username, actor=auth_data.username, ip_address=context.ip_address
    )
    if not success:
        msg = "Specified user is not an administrator"
        raise NotFoundError(msg, ErrorLocation.path, ["username"])


@router.get(
    "/auth/api/v1/history/token-changes",
    description=(
        "Get the change history of tokens for any user. If a limit or cursor"
        " was specified, links to paginated results may be found in the `Link`"
        " header of the reply and the total number of records in the"
        " `X-Total-Count` header."
    ),
    responses={200: {"headers": _pagination_headers}},
    response_model=list[TokenChangeHistoryEntry],
    response_model_exclude_unset=True,
    summary="Get token change history",
    tags=["admin"],
)
async def get_admin_token_change_history(
    *,
    cursor: Annotated[
        str | None,
        Query(
            title="Cursor",
            description="Pagination cursor",
            examples=["1614985055_4234"],
            pattern=CURSOR_REGEX,
        ),
    ] = None,
    limit: Annotated[
        int | None,
        Query(
            title="Row limit",
            description="Maximum number of entries to return",
            examples=[500],
            ge=1,
        ),
    ] = None,
    since: Annotated[
        UtcDatetime | None,
        Query(
            title="Not before",
            description="Only show entries at or after this time",
            examples=["2021-03-05T14:59:52Z"],
        ),
    ] = None,
    until: Annotated[
        UtcDatetime | None,
        Query(
            title="Not after",
            description="Only show entries before or at this time",
            examples=["2021-03-05T14:59:52Z"],
        ),
    ] = None,
    username: Annotated[
        str | None,
        Query(
            title="Username",
            description="Only show tokens for this user",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ] = None,
    actor: Annotated[
        str | None,
        Query(
            title="Actor",
            description="Only show actions performed by this user",
            examples=["adminuser"],
            min_length=1,
            max_length=64,
            pattern=ACTOR_REGEX,
        ),
    ] = None,
    key: Annotated[
        str | None,
        Query(
            title="Token",
            description="Only show changes for this token",
            examples=["dDQg_NTNS51GxeEteqnkag"],
            min_length=22,
            max_length=22,
        ),
    ] = None,
    token_type: Annotated[
        TokenType | None,
        Query(
            title="Token type",
            description="Only show tokens of this type",
            examples=["user"],
        ),
    ] = None,
    ip_address: Annotated[
        str | None,
        Query(
            title="IP or CIDR",
            description="Only show changes from this IP or CIDR block",
            examples=["198.51.100.0/24"],
        ),
    ] = None,
    auth_data: Annotated[TokenData, Depends(authenticate_admin_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> list[dict[str, Any]]:
    token_service = context.factory.create_token_service()
    parsed_cursor = None
    if cursor:
        parsed_cursor = TokenChangeHistoryCursor.from_str(cursor)
    results = await token_service.get_change_history(
        auth_data,
        cursor=parsed_cursor,
        limit=limit,
        since=since,
        until=until,
        username=username,
        actor=actor,
        key=key,
        token_type=token_type,
        ip_or_cidr=ip_address,
    )
    if limit:
        response.headers["Link"] = results.link_header(context.request.url)
        response.headers["X-Total-Count"] = str(results.count)
    return [r.model_dump_reduced() for r in results.entries]


@router.get(
    "/auth/api/v1/login",
    description=(
        "Used by the JavaScript UI to obtain a CSRF token, user metadata,"
        " and server configuration. Not used with regular API calls."
    ),
    summary="Initialize UI",
    tags=["browser"],
)
async def get_login(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_session_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> APILoginResponse:
    if not context.state.csrf:
        context.state.csrf = random_128_bits()
    known_scopes = [
        Scope(name=n, description=d)
        for n, d in sorted(context.config.known_scopes.items())
    ]
    api_config = APIConfig(scopes=known_scopes)
    return APILoginResponse(
        csrf=context.state.csrf,
        username=auth_data.username,
        scopes=auth_data.scopes,
        config=api_config,
    )


@router.get(
    "/auth/api/v1/quota-overrides",
    description="Return the current quota overrides if any",
    response_model_exclude_none=True,
    responses={
        404: {"description": "No quota overrides set", "model": ErrorModel}
    },
    summary="Get quota overrides",
    tags=["admin"],
)
async def get_quota_overrides(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> QuotaConfig:
    user_info_service = context.factory.create_user_info_service()
    overrides = await user_info_service.get_quota_overrides()
    if overrides:
        return overrides
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=[{"type": "not_found", "msg": "No quota overrides set"}],
        )


@router.delete(
    "/auth/api/v1/quota-overrides",
    description="Remove any existing quota overrides",
    responses={
        404: {"description": "No quota overrides set", "model": ErrorModel}
    },
    status_code=204,
    summary="Remove quota overrides",
    tags=["admin"],
)
async def delete_quota_overrides(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_admin_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> None:
    user_info_service = context.factory.create_user_info_service()
    success = await user_info_service.delete_quota_overrides()
    if success:
        context.logger.info("Deleted quota overrides")
    else:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=[{"type": "not_found", "msg": "No quota overrides set"}],
        )


@router.put(
    "/auth/api/v1/quota-overrides",
    description="Set the quota overrides",
    response_model_exclude_none=True,
    summary="Set quota overrides",
    tags=["admin"],
)
async def put_quota_overrides(
    overrides: QuotaConfig,
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_admin_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> QuotaConfig:
    user_info_service = context.factory.create_user_info_service()
    await user_info_service.set_quota_overrides(overrides)
    context.logger.info(
        "Updated quota overrides",
        quota_overrides=overrides.model_dump(mode="json"),
    )
    return overrides


@router.get(
    "/auth/api/v1/token-info",
    description="Return metadata about the authentication token",
    response_model_exclude_none=True,
    responses={404: {"description": "Token not found", "model": ErrorModel}},
    summary="Get token details",
    tags=["user"],
)
async def get_token_info(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    info = await token_service.get_token_info_unchecked(auth_data.token.key)
    if info:
        return info
    else:
        msg = "Token found in Redis but not database"
        context.logger.warning(msg)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=[{"type": "invalid_token", "msg": msg}],
        )


@router.post(
    "/auth/api/v1/tokens",
    responses={
        201: {
            "headers": {
                "Location": {
                    "description": "URL of new token",
                    "schema": {"type": "string"},
                }
            }
        }
    },
    status_code=201,
    summary="Create a token",
    tags=["admin"],
)
async def post_admin_tokens(
    *,
    token_request: AdminTokenRequest,
    auth_data: Annotated[TokenData, Depends(authenticate_admin_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> NewToken:
    token_service = context.factory.create_token_service()
    token = await token_service.create_token_from_admin_request(
        token_request, auth_data, ip_address=context.ip_address
    )
    response.headers["Location"] = quote(
        f"/auth/api/v1/users/{token_request.username}/tokens/{token.key}"
    )
    return NewToken(token=str(token))


@router.get(
    "/auth/api/v1/user-info",
    description="Get metadata about the autheticated user",
    response_model_exclude_none=True,
    summary="Get user metadata",
    tags=["user"],
)
async def get_user_info(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> UserInfo:
    user_info_service = context.factory.create_user_info_service()
    try:
        return await user_info_service.get_user_info_from_token(auth_data)
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


@router.get(
    "/auth/api/v1/users/{username}/token-change-history",
    description=(
        "Get the change history of tokens for the current user. If a limit"
        " or cursor was specified, links to paginated results may be found"
        " in the `Link` header of the reply and the total number of records"
        " in the `X-Total-Count` header."
    ),
    responses={200: {"headers": _pagination_headers}},
    response_model=list[TokenChangeHistoryEntry],
    response_model_exclude_unset=True,
    summary="Get token change history",
    tags=["user"],
)
async def get_user_token_change_history(
    *,
    username: Annotated[
        str,
        Path(
            title="Username",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    cursor: Annotated[
        str | None,
        Query(
            title="Cursor",
            description="Pagination cursor",
            examples=["1614985055_4234"],
            pattern=CURSOR_REGEX,
        ),
    ] = None,
    limit: Annotated[
        int | None,
        Query(
            title="Row limit",
            description="Maximum number of entries to return",
            examples=[500],
            ge=1,
        ),
    ] = None,
    since: Annotated[
        UtcDatetime | None,
        Query(
            title="Not before",
            description="Only show entries at or after this time",
            examples=["2021-03-05T14:59:52Z"],
        ),
    ] = None,
    until: Annotated[
        UtcDatetime | None,
        Query(
            title="Not after",
            description="Only show entries before or at this time",
            examples=["2021-03-05T14:59:52Z"],
        ),
    ] = None,
    key: Annotated[
        str | None,
        Query(
            title="Token",
            description="Only show changes for this token",
            examples=["dDQg_NTNS51GxeEteqnkag"],
            min_length=22,
            max_length=22,
        ),
    ] = None,
    token_type: Annotated[
        TokenType | None,
        Query(
            title="Token type",
            description="Only show tokens of this type",
            examples=["user"],
        ),
    ] = None,
    ip_address: Annotated[
        str | None,
        Query(
            title="IP or CIDR",
            description="Only show changes from this IP or CIDR block",
            examples=["198.51.100.0/24"],
        ),
    ] = None,
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> list[dict[str, Any]]:
    token_service = context.factory.create_token_service()
    parsed_cursor = None
    if cursor:
        parsed_cursor = TokenChangeHistoryCursor.from_str(cursor)
    results = await token_service.get_change_history(
        auth_data,
        cursor=parsed_cursor,
        username=username,
        limit=limit,
        since=since,
        until=until,
        key=key,
        token_type=token_type,
        ip_or_cidr=ip_address,
    )
    if limit:
        response.headers["Link"] = results.link_header(context.request.url)
        response.headers["X-Total-Count"] = str(results.count)
    return [r.model_dump_reduced() for r in results.entries]


@router.get(
    "/auth/api/v1/users/{username}",
    response_model_exclude_defaults=True,
    summary="Get user information",
    description=(
        "Only information from LDAP is displayed. Queries for bot users will"
        " not contain any useful information unless they also exist in LDAP,"
        " and Gafaelfawr installations using GitHub for authentication will"
        " return 404 errors for all users since LDAP is not configured."
    ),
    responses={404: {"description": "LDAP is not configured"}},
    tags=["admin"],
)
async def get_user(
    *,
    username: Annotated[
        str,
        Path(
            title="Username",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> UserInfo:
    user_info_service = context.factory.create_user_info_service()
    return await user_info_service.get_user_info_from_ldap(auth_data, username)


@router.get(
    "/auth/api/v1/users/{username}/tokens",
    response_model_exclude_none=True,
    summary="List tokens",
    tags=["user"],
)
async def get_tokens(
    *,
    username: Annotated[
        str,
        Path(
            title="Username",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> list[TokenInfo]:
    token_service = context.factory.create_token_service()
    return await token_service.list_tokens(auth_data, username)


@router.post(
    "/auth/api/v1/users/{username}/tokens",
    responses={
        201: {
            "headers": {
                "Location": {
                    "description": "URL of new token",
                    "schema": {"type": "string"},
                }
            }
        }
    },
    status_code=201,
    summary="Create user token",
    tags=["user"],
)
async def post_tokens(
    *,
    token_request: UserTokenRequest,
    username: Annotated[
        str,
        Path(
            title="Username",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    auth_data: Annotated[TokenData, Depends(authenticate_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> NewToken:
    token_service = context.factory.create_token_service()
    token_params = token_request.model_dump()
    token = await token_service.create_user_token(
        auth_data,
        username,
        ip_address=context.ip_address,
        **token_params,
    )
    response.headers["Location"] = quote(
        f"/auth/api/v1/users/{username}/tokens/{token.key}"
    )
    return NewToken(token=str(token))


@router.get(
    "/auth/api/v1/users/{username}/tokens/{key}",
    response_model_exclude_none=True,
    responses={404: {"description": "Token not found", "model": ErrorModel}},
    summary="Get token metadata",
    tags=["user"],
)
async def get_token(
    *,
    username: Annotated[
        str,
        Path(
            title="Username",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    key: Annotated[
        str,
        Path(
            title="Token key",
            examples=["GpbIL3_qhgZlpfGTFF"],
            min_length=22,
            max_length=22,
        ),
    ],
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    info = await token_service.get_token_info(key, auth_data, username)
    if info:
        return info
    else:
        raise NotFoundError("Token not found", ErrorLocation.path, ["key"])


@router.delete(
    "/auth/api/v1/users/{username}/tokens/{key}",
    responses={404: {"description": "Token not found", "model": ErrorModel}},
    summary="Revoke token",
    status_code=204,
    tags=["user"],
)
async def delete_token(
    *,
    username: Annotated[
        str,
        Path(
            title="Username",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    key: Annotated[
        str,
        Path(
            title="Token key",
            examples=["GpbIL3_qhgZlpfGTFF"],
            min_length=22,
            max_length=22,
        ),
    ],
    auth_data: Annotated[TokenData, Depends(authenticate_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> None:
    token_service = context.factory.create_token_service()
    success = await token_service.delete_token(
        key, auth_data, username, ip_address=context.ip_address
    )
    if not success:
        raise NotFoundError("Token not found", ErrorLocation.path, ["key"])


@router.patch(
    "/auth/api/v1/users/{username}/tokens/{key}",
    description=(
        "Replace metadata of a user token with provided values. Only the"
        " token name, scope, and expiration may be changed. Only token"
        " administrators may modify tokens; users cannot modify even their"
        " own tokens and should instead create a new token and delete the"
        " old one."
    ),
    response_model_exclude_none=True,
    responses={404: {"description": "Token not found", "model": ErrorModel}},
    status_code=200,
    summary="Modify user token",
    tags=["admin"],
)
async def patch_token(
    *,
    token_request: UserTokenModifyRequest,
    username: Annotated[
        str,
        Path(
            title="Username",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    key: Annotated[
        str,
        Path(
            title="Token key",
            examples=["GpbIL3_qhgZlpfGTFF"],
            min_length=22,
            max_length=22,
        ),
    ],
    auth_data: Annotated[TokenData, Depends(authenticate_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    update = token_request.model_dump(exclude_unset=True)
    if "expires" in update and update["expires"] is None:
        update["no_expire"] = True
    info = await token_service.modify_token(
        key, auth_data, username, ip_address=context.ip_address, **update
    )
    if not info:
        raise NotFoundError("Token not found", ErrorLocation.path, ["key"])
    return info


@router.get(
    "/auth/api/v1/users/{username}/tokens/{key}/change-history",
    response_model=list[TokenChangeHistoryEntry],
    response_model_exclude_unset=True,
    responses={404: {"description": "Token not found", "model": ErrorModel}},
    summary="Get change history of token",
    description="All changes are returned. Pagination is not supported.",
    tags=["user"],
)
async def get_token_change_history(
    *,
    username: Annotated[
        str,
        Path(
            title="Username",
            examples=["someuser"],
            min_length=1,
            max_length=64,
            pattern=USERNAME_REGEX,
        ),
    ],
    key: Annotated[
        str,
        Path(
            title="Token key",
            examples=["GpbIL3_qhgZlpfGTFF"],
            min_length=22,
            max_length=22,
        ),
    ],
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> list[dict[str, Any]]:
    token_service = context.factory.create_token_service()
    results = await token_service.get_change_history(
        auth_data, username=username, key=key
    )
    if not results.entries:
        raise NotFoundError("Token not found", ErrorLocation.path, ["key"])
    return [r.model_dump_reduced() for r in results.entries]
