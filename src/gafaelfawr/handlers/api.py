"""Route handlers for the token API.

All the route handlers are intentionally defined in a single file to encourage
the implementation to be very short. All the business logic should be defined
in manager objects and the output formatting should be handled by response
models.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from safir.models import ErrorLocation, ErrorModel
from safir.pydantic import UtcDatetime
from safir.sentry import report_exception
from safir.slack.webhook import SlackRouteErrorHandler

from ..constants import (
    ACTOR_REGEX,
    CURSOR_REGEX,
    GITHUB_BOT_USERNAME_REGEX,
    GITHUB_REPOSITORY_REGEX,
    USERNAME_REGEX,
)
from ..dependencies.auth import AuthenticateRead, AuthenticateWrite
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import (
    ExternalUserInfoError,
    GitHubError,
    GitHubWebError,
    NotFoundError,
)
from ..models.auth import APIConfig, APILoginResponse, Scope
from ..models.enums import TokenType
from ..models.github_project import (
    GitHubProject,
    GitHubProjectCreate,
    GitHubProjectUpdate,
)
from ..models.history import TokenChangeHistoryCursor, TokenChangeHistoryEntry
from ..models.oidc import OIDCClient, OIDCClientUpdate, OIDCClientWithSecret
from ..models.quota import QuotaConfig
from ..models.token import (
    AdminTokenRequest,
    NewToken,
    TokenData,
    TokenInfo,
    UserTokenModifyRequest,
    UserTokenRequest,
)
from ..models.userinfo import AllGroups, UserInfo
from ..util import random_128_bits

router = APIRouter(route_class=SlackRouteErrorHandler)
"""Router for API routes."""

__all__ = ["router"]

authenticate_read = AuthenticateRead()
authenticate_write = AuthenticateWrite()
authenticate_admin_read = AuthenticateRead(
    require_scope="admin:token", allow_bootstrap_token=True
)
authenticate_admin_write = AuthenticateWrite(require_scope="admin:token")
authenticate_admin_write_bootstrap = AuthenticateWrite(
    require_scope="admin:token", allow_bootstrap_token=True
)
authenticate_oidc_admin_read = AuthenticateRead(
    require_scope="admin:oidc", allow_bootstrap_token=True
)
authenticate_oidc_admin_write = AuthenticateWrite(
    require_scope="admin:oidc", allow_bootstrap_token=True
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


_GITHUB_PROJECT_ID = Path(
    title="Project ID",
    description="Unique identifier of the GitHub project",
    examples=[42],
    ge=1,
)

_github_project_responses: dict[int | str, dict[str, Any]] = {
    404: {
        "description": (
            "GitHub Actions token exchange not configured or project not found"
        ),
        "model": ErrorModel,
    },
}

_github_project_write_responses: dict[int | str, dict[str, Any]] = {
    422: {
        "description": (
            "The repository was not found on GitHub or is not public"
            " (`unknown_repository`), the username derived from the"
            " repository is not a valid username (`invalid_username`), the"
            " scopes are unknown or not allowed (`invalid_scopes`), or the"
            " maximum lifetime exceeds the configured limit"
            " (`invalid_max_lifetime`)"
        ),
        "model": ErrorModel,
    },
    502: {
        "description": (
            "GitHub could not be contacted or returned an error while"
            " looking up the repository (`github_unavailable`). Nothing was"
            " changed, so retry the request later."
        ),
        "model": ErrorModel,
    },
}


@asynccontextmanager
async def _report_github_failure(
    context: RequestContext,
) -> AsyncIterator[None]:
    """Convert a failed GitHub repository lookup into a 502 error.

    Repository lookups are unauthenticated and therefore subject to GitHub's
    low anonymous rate limit, and GitHub may be down. Those failures are
    upstream problems that the caller should retry, so report them to Slack
    and Sentry and return a Bad Gateway error with an
    `~safir.models.ErrorModel` body rather than letting them propagate as an
    uncaught exception.

    Parameters
    ----------
    context
        Context of the request.

    Raises
    ------
    fastapi.HTTPException
        Raised with status 502 if the body of the context manager raised a
        GitHub error.
    """
    try:
        yield
    except (GitHubError, GitHubWebError) as e:
        msg = "GitHub repository lookup failed, retry later"
        context.logger.exception(msg, error=str(e))
        slack_client = context.factory.create_slack_client()
        await report_exception(e, slack_client=slack_client)
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=[{"msg": msg, "type": "github_unavailable"}],
        ) from e


@router.get(
    "/auth/api/v1/github/projects",
    description=(
        "List the registered GitHub projects, optionally limited to those"
        " matching every given filter. Projects are the trust configuration"
        " of the GitHub Actions token exchange and say which GitHub"
        " workflows may obtain Gafaelfawr tokens, as which bot user, with"
        " which scopes, and for how long."
    ),
    responses={
        404: {
            "description": "GitHub Actions token exchange not configured",
            "model": ErrorModel,
        },
    },
    summary="List GitHub projects",
    tags=["admin"],
)
async def get_github_projects(
    *,
    repository: Annotated[
        str | None,
        Query(
            title="Repository",
            description=(
                "Limit the results to projects for this GitHub repository,"
                " given as ``owner/name`` and compared case-insensitively"
            ),
            examples=["lsst-sqre/sqr-062"],
            min_length=3,
            max_length=140,
            pattern=GITHUB_REPOSITORY_REGEX,
        ),
    ] = None,
    username: Annotated[
        str | None,
        Query(
            title="Bot username",
            description=(
                "Limit the results to projects that mint tokens for this"
                " bot username"
            ),
            examples=["bot-gh-lsst-sqre-sqr-062"],
            min_length=1,
            max_length=64,
            pattern=GITHUB_BOT_USERNAME_REGEX,
        ),
    ] = None,
    template: Annotated[
        str | None,
        Query(
            title="Template",
            description=(
                "Limit the results to projects provisioned from this project"
                " template"
            ),
            examples=["technote"],
            min_length=1,
            max_length=64,
        ),
    ] = None,
    requested_by: Annotated[
        str | None,
        Query(
            title="Requested by",
            description=(
                "Limit the results to projects created on behalf of this"
                " identifier, as ``<source>:<identifier>``"
            ),
            examples=["slack:U024BE7LH"],
            min_length=1,
            max_length=256,
        ),
    ] = None,
    auth_data: Annotated[TokenData, Depends(authenticate_admin_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> list[GitHubProject]:
    project_service = context.factory.create_github_project_service()
    return await project_service.list_projects(
        auth_data,
        repository=repository,
        username=username,
        template=template,
        requested_by=requested_by,
    )


@router.post(
    "/auth/api/v1/github/projects",
    description=(
        "Register a new GitHub project. The repository must be a public"
        " GitHub repository; its numeric GitHub IDs are looked up and pinned"
        " so that the project keeps trusting the original repository if the"
        " name is later reused. If no username is given, one is derived from"
        " the repository as ``bot-gh-<owner>-<repo>``. The project is"
        " refused if it is enabled and its constraints overlap those of an"
        " existing enabled project for the same repository, since at most"
        " one project may match a token. The response is the stored project,"
        " including the resolved username and pinned IDs, which the caller"
        " should check against the intended repository."
    ),
    responses={
        201: {
            "headers": {
                "Location": {
                    "description": "URL of the new project",
                    "schema": {"type": "string"},
                }
            }
        },
        404: {
            "description": "GitHub Actions token exchange not configured",
            "model": ErrorModel,
        },
        409: {
            "description": (
                "Constraints overlap an existing project, or the derived"
                " username is already used by a project for another"
                " repository. The error message names the conflicting"
                " project."
            ),
            "model": ErrorModel,
        },
        **_github_project_write_responses,
    },
    status_code=201,
    summary="Create a GitHub project",
    tags=["admin"],
)
async def post_github_projects(
    *,
    create: GitHubProjectCreate,
    auth_data: Annotated[
        TokenData, Depends(authenticate_admin_write_bootstrap)
    ],
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> GitHubProject:
    project_service = context.factory.create_github_project_service()
    async with _report_github_failure(context):
        project = await project_service.create_project(
            create, auth_data, ip_address=context.ip_address
        )
    url = context.request.url_for("get_github_project", project_id=project.id)
    response.headers["Location"] = str(url)
    return project


@router.get(
    "/auth/api/v1/github/projects/{project_id}",
    description="Get details about a GitHub project",
    responses=_github_project_responses,
    summary="Get a GitHub project",
    tags=["admin"],
)
async def get_github_project(
    *,
    project_id: Annotated[int, _GITHUB_PROJECT_ID],
    auth_data: Annotated[TokenData, Depends(authenticate_admin_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> GitHubProject:
    project_service = context.factory.create_github_project_service()
    return await project_service.get_project(project_id, auth_data)


@router.delete(
    "/auth/api/v1/github/projects/{project_id}",
    description=(
        "Delete a GitHub project and revoke every token minted for it that"
        " is still outstanding"
    ),
    responses=_github_project_responses,
    status_code=204,
    summary="Delete a GitHub project",
    tags=["admin"],
)
async def delete_github_project(
    *,
    project_id: Annotated[int, _GITHUB_PROJECT_ID],
    auth_data: Annotated[
        TokenData, Depends(authenticate_admin_write_bootstrap)
    ],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> None:
    project_service = context.factory.create_github_project_service()
    await project_service.delete_project(
        project_id, auth_data, ip_address=context.ip_address
    )


@router.patch(
    "/auth/api/v1/github/projects/{project_id}",
    description=(
        "Modify a GitHub project. Only the fields present in the request"
        " are changed, and setting an optional field to null clears it."
        " Changing the repository looks up its numeric IDs again but keeps"
        " the username unless it is also changed. Setting the username to"
        " null derives it from the repository again. Changes to the"
        " constraints are checked for overlap with other enabled projects"
        " as on creation. Setting ``enabled`` to false revokes every"
        " outstanding token minted for the project; other changes do not"
        " affect tokens already minted."
    ),
    responses={
        **_github_project_responses,
        409: {
            "description": (
                "Constraints would overlap an existing project, or the"
                " derived username is already used by a project for another"
                " repository. The error message names the conflicting"
                " project."
            ),
            "model": ErrorModel,
        },
        **_github_project_write_responses,
    },
    summary="Update a GitHub project",
    tags=["admin"],
)
async def patch_github_project(
    *,
    project_id: Annotated[int, _GITHUB_PROJECT_ID],
    update: GitHubProjectUpdate,
    auth_data: Annotated[
        TokenData, Depends(authenticate_admin_write_bootstrap)
    ],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> GitHubProject:
    project_service = context.factory.create_github_project_service()
    async with _report_github_failure(context):
        return await project_service.update_project(
            project_id, update, auth_data, ip_address=context.ip_address
        )


@router.get(
    "/auth/api/v1/groups",
    description=(
        "Only information from LDAP is displayed. Gafaelfawr installations"
        " using GitHub for authentication will return a 404 error since LDAP"
        " is not configured."
    ),
    response_model_exclude_defaults=True,
    responses={404: {"description": "LDAP is not configured"}},
    summary="List known groups",
    tags=["admin"],
)
async def list_groups(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> AllGroups:
    user_info_service = context.factory.create_user_info_service()
    return await user_info_service.get_groups_from_ldap(auth_data)


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
        "Used by Squareone to obtain a CSRF token, user metadata, and server"
        " configuration. Not used with regular API calls."
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


def get_oidc_client_url(request: Request, client_id: str) -> str:
    """Return the URL for a given registered OpenID Connect client."""
    return str(request.url_for("get_oidc_client", client_id=client_id))


@router.get(
    "/auth/api/v1/oidc-clients",
    description="List the current registered OpenID Connect clients",
    response_model_exclude_none=True,
    responses={
        404: {
            "description": "OpenID Connect server not configured",
            "model": ErrorModel,
        },
    },
    summary="Get OIDC clients",
    tags=["admin"],
)
async def get_oidc_clients(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_oidc_admin_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> list[OIDCClient]:
    oidc_service = context.factory.create_oidc_service()
    clients = await oidc_service.list_clients(auth_data)
    for client in clients:
        client.url = get_oidc_client_url(context.request, client.client_id)
    return clients


@router.post(
    "/auth/api/v1/oidc-clients",
    description=(
        "Register a new OpenID Connect client. The secret returned in the"
        " response to this request cannot be retrieved again. The client is"
        " responsible for saving it. If the secret is lost, the client must"
        " be recreated to set a new secret."
    ),
    response_model_exclude_none=True,
    responses={
        404: {
            "description": "OpenID Connect server not configured",
            "model": ErrorModel,
        },
    },
    status_code=201,
    summary="Add OIDC client",
    tags=["admin"],
)
async def add_oidc_client(
    *,
    create_request: OIDCClientUpdate,
    auth_data: Annotated[TokenData, Depends(authenticate_oidc_admin_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> OIDCClientWithSecret:
    oidc_service = context.factory.create_oidc_service()
    client = await oidc_service.register_client(auth_data, create_request)
    client.url = get_oidc_client_url(context.request, client.client_id)
    response.headers["Location"] = client.url
    return client


@router.get(
    "/auth/api/v1/oidc-clients/{client_id}",
    description="Get details about an OpenID Connect client",
    response_model_exclude_none=True,
    responses={
        404: {
            "description": "OpenID Connect client not found",
            "model": ErrorModel,
        },
    },
    summary="Get an OIDC client",
    tags=["admin"],
)
async def get_oidc_client(
    *,
    client_id: str,
    auth_data: Annotated[TokenData, Depends(authenticate_oidc_admin_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> OIDCClient:
    oidc_service = context.factory.create_oidc_service()
    client = await oidc_service.get_client(auth_data, client_id)
    client.url = get_oidc_client_url(context.request, client.client_id)
    return client


@router.delete(
    "/auth/api/v1/oidc-clients/{client_id}",
    description="Delete an OpenID Connect client",
    responses={
        404: {
            "description": "OpenID Connect client not found",
            "model": ErrorModel,
        },
    },
    status_code=204,
    summary="Delete an OIDC client",
    tags=["admin"],
)
async def delete_oidc_client(
    *,
    client_id: str,
    auth_data: Annotated[TokenData, Depends(authenticate_oidc_admin_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> None:
    oidc_service = context.factory.create_oidc_service()
    await oidc_service.delete_client(auth_data, client_id)


@router.patch(
    "/auth/api/v1/oidc-clients/{client_id}",
    description="Update an OpenID Connect client",
    responses={
        404: {
            "description": "OpenID Connect client not found",
            "model": ErrorModel,
        },
    },
    summary="Update an OIDC client",
    tags=["admin"],
)
async def patch_oidc_client(
    *,
    client_id: str,
    update: OIDCClientUpdate,
    auth_data: Annotated[TokenData, Depends(authenticate_oidc_admin_write)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> OIDCClient:
    oidc_service = context.factory.create_oidc_service()
    client = await oidc_service.update_client(auth_data, client_id, update)
    client.url = get_oidc_client_url(context.request, client.client_id)
    return client


@router.get(
    "/auth/api/v1/quota-overrides",
    description="Return the current quota overrides if any",
    response_model_exclude_defaults=True,
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
    response_model_exclude_defaults=True,
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
    auth_data: Annotated[
        TokenData, Depends(authenticate_admin_write_bootstrap)
    ],
    context: Annotated[RequestContext, Depends(context_dependency)],
    response: Response,
) -> NewToken:
    token_service = context.factory.create_token_service()
    token = await token_service.create_token_from_admin_request(
        token_request, auth_data, ip_address=context.ip_address
    )
    url = context.request.url_for(
        "get_token", username=token_request.username, key=token.key
    )
    response.headers["Location"] = str(url)
    return NewToken(token=str(token))


@router.get(
    "/auth/api/v1/user-info",
    description="Get metadata about the autheticated user",
    response_model_exclude_defaults=True,
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
        await report_exception(e, slack_client=slack_client)
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
    response_model=list[TokenChangeHistoryEntry],
    response_model_exclude_unset=True,
    responses={200: {"headers": _pagination_headers}},
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
    "/auth/api/v1/users",
    description=(
        "Only information from LDAP is displayed. Bot users will not be"
        " listed unless they also exist in LDAP. Gafaelfawr installations"
        " using GitHub for authentication will return a 404 error since LDAP"
        " is not configured."
    ),
    response_model_exclude_defaults=True,
    responses={404: {"description": "LDAP is not configured"}},
    summary="List known users",
    tags=["admin"],
)
async def list_users(
    *,
    auth_data: Annotated[TokenData, Depends(authenticate_read)],
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> list[UserInfo]:
    user_info_service = context.factory.create_user_info_service()
    return await user_info_service.get_users_from_ldap(auth_data)


@router.get(
    "/auth/api/v1/users/{username}",
    description=(
        "Only information from LDAP is displayed. Queries for bot users will"
        " not contain any useful information unless they also exist in LDAP,"
        " and Gafaelfawr installations using GitHub for authentication will"
        " return 404 errors for all users since LDAP is not configured."
    ),
    response_model_exclude_defaults=True,
    responses={404: {"description": "LDAP is not configured"}},
    summary="Get user information",
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
    key = token.key
    url = context.request.url_for("get_token", username=username, key=key)
    response.headers["Location"] = str(url)
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
    description="All changes are returned. Pagination is not supported.",
    response_model=list[TokenChangeHistoryEntry],
    response_model_exclude_unset=True,
    responses={404: {"description": "Token not found", "model": ErrorModel}},
    summary="Get change history of token",
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
