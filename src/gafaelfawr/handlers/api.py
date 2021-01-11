"""Route handlers for the ``/auth/api/v1`` API.

All the route handlers are intentionally defined in a single file to encourage
the implementation to be very short.  All the business logic should be defined
in manager objects and the output formatting should be handled by response
models.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response, status

from gafaelfawr.dependencies.auth import Authenticate
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.dependencies.csrf import set_csrf, verify_csrf
from gafaelfawr.exceptions import (
    BadExpiresError,
    BadScopesError,
    DuplicateTokenNameError,
)
from gafaelfawr.models.admin import Admin
from gafaelfawr.models.auth import APIConfig, APILoginResponse, Scope
from gafaelfawr.models.token import (
    NewToken,
    TokenData,
    TokenInfo,
    TokenUserInfo,
    UserTokenModifyRequest,
    UserTokenRequest,
)

__all__ = ["router"]

router = APIRouter()
authenticate = Authenticate()
authenticate_admin = Authenticate(
    require_scope="admin:token", allow_bootstrap_token=True
)
authenticate_session = Authenticate(require_session=True)


@router.get(
    "/admins",
    response_model=List[Admin],
    responses={403: {"description": "Permission denied"}},
    dependencies=[Depends(authenticate_admin)],
)
def get_admins(
    context: RequestContext = Depends(context_dependency),
) -> List[Admin]:
    admin_service = context.factory.create_admin_service()
    return admin_service.get_admins()


@router.get(
    "/login",
    response_model=APILoginResponse,
    responses={307: {"description": "Not currently authenticated"}},
    dependencies=[Depends(set_csrf)],
)
def get_login(
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> APILoginResponse:
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
    "/token-info",
    response_model=TokenInfo,
    response_model_exclude_none=True,
    responses={404: {"description": "Token not found"}},
)
async def get_token_info(
    auth_data: TokenData = Depends(authenticate),
    context: RequestContext = Depends(context_dependency),
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    info = token_service.get_token_info_unchecked(auth_data.token.key)
    if not info:
        msg = "Token found in Redis but not database"
        context.logger.warning(msg)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"type": "invalid_token", "msg": msg},
        )
    else:
        return info


@router.get("/user-info", response_model=TokenUserInfo)
async def get_user_info(
    auth_data: TokenData = Depends(authenticate),
) -> TokenUserInfo:
    return auth_data


@router.get(
    "/users/{username}/tokens",
    response_model=List[TokenInfo],
    response_model_exclude_none=True,
)
async def get_tokens(
    username: str,
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> List[TokenInfo]:
    token_service = context.factory.create_token_service()
    return token_service.list_tokens(auth_data, username)


@router.post(
    "/users/{username}/tokens",
    status_code=201,
    dependencies=[Depends(verify_csrf)],
)
async def post_tokens(
    username: str,
    token_request: UserTokenRequest,
    response: Response,
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> NewToken:
    token_service = context.factory.create_token_service()
    token_params = token_request.dict(exclude_unset=True)
    if "expires" not in token_params or token_params["expires"] is None:
        token_params["no_expire"] = True
    try:
        token = await token_service.create_user_token(
            auth_data, username, **token_params
        )
    except BadExpiresError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "expires"],
                "type": "bad_expires",
                "msg": str(e),
            },
        )
    except BadScopesError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "scopes"],
                "type": "bad_scopes",
                "msg": str(e),
            },
        )
    except DuplicateTokenNameError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "token_name"],
                "type": "duplicate_token_name",
                "msg": str(e),
            },
        )
    token_url = f"/auth/api/v1/users/{username}/tokens/{token.key}"
    response.headers["Location"] = token_url
    return NewToken(token=str(token))


@router.get(
    "/users/{username}/tokens/{key}",
    response_model=TokenInfo,
    response_model_exclude_none=True,
)
async def get_token(
    username: str,
    key: str,
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    info = token_service.get_token_info(key, auth_data, username)
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "token"],
                "type": "not_found",
                "msg": "Token not found",
            },
        )
    return info


@router.delete(
    "/users/{username}/tokens/{key}",
    status_code=204,
    dependencies=[Depends(verify_csrf)],
)
async def delete_token(
    username: str,
    key: str,
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> None:
    token_service = context.factory.create_token_service()
    success = await token_service.delete_token(key, auth_data, username)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "token"],
                "type": "not_found",
                "msg": "Token not found",
            },
        )


@router.patch(
    "/users/{username}/tokens/{key}",
    status_code=201,
    response_model=TokenInfo,
    response_model_exclude_none=True,
    dependencies=[Depends(verify_csrf)],
)
async def patch_token(
    username: str,
    key: str,
    token_request: UserTokenModifyRequest,
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> TokenInfo:
    token_service = context.factory.create_token_service()
    update = token_request.dict(exclude_unset=True)
    if "expires" in update and update["expires"] is None:
        update["no_expire"] = True
    try:
        info = await token_service.modify_token(
            key, auth_data, username, **update
        )
    except BadExpiresError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "expires"],
                "type": "bad_expires",
                "msg": str(e),
            },
        )
    except BadScopesError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "scopes"],
                "type": "bad_scopes",
                "msg": str(e),
            },
        )
    except DuplicateTokenNameError as e:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "loc": ["body", "token_name"],
                "type": "duplicate_token_name",
                "msg": str(e),
            },
        )
    if not info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "token"],
                "type": "not_found",
                "msg": "Token not found",
            },
        )
    return info
