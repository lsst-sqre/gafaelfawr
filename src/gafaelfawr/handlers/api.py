"""Route handlers for the ``/auth/api/v1`` API.

All the route handlers are intentionally defined in a single file to encourage
the implementation to be very short.  All the business logic should be defined
in manager objects and the output formatting should be handled by response
models.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Response, status

from gafaelfawr.dependencies.auth import (
    authenticate,
    authenticate_session,
    require_admin,
)
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.dependencies.csrf import set_csrf
from gafaelfawr.exceptions import PermissionDeniedError
from gafaelfawr.models.admin import Admin
from gafaelfawr.models.auth import APILoginResponse
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
"""Router for ``/auth/api/v1`` handlers."""


@router.get(
    "/admins",
    response_model=List[Admin],
    responses={403: {"description": "Permission denied"}},
    dependencies=[Depends(require_admin)],
)
def get_admins(
    context: RequestContext = Depends(context_dependency),
) -> List[Admin]:
    admin_manager = context.factory.create_admin_manager()
    return admin_manager.get_admins()


@router.get(
    "/login",
    response_model=APILoginResponse,
    responses={307: {"description": "Not currently authenticated"}},
    dependencies=[
        Depends(authenticate_session),
        Depends(set_csrf),
    ],
)
def get_login(
    context: RequestContext = Depends(context_dependency),
) -> APILoginResponse:
    return APILoginResponse(csrf=context.state.csrf)


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
    token_manager = context.factory.create_token_manager()
    info = token_manager.get_info(auth_data.token.key)
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
    token_manager = context.factory.create_token_manager()
    return token_manager.list_tokens(auth_data)


@router.post("/users/{username}/tokens", status_code=201)
async def post_tokens(
    username: str,
    token_request: UserTokenRequest,
    response: Response,
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> NewToken:
    token_manager = context.factory.create_token_manager()
    token_params = token_request.dict(exclude_unset=True)
    token = await token_manager.create_user_token(auth_data, **token_params)
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
    if username != auth_data.username:
        msg = f"{auth_data.username} cannot list tokens for {username}"
        raise PermissionDeniedError(msg)
    token_manager = context.factory.create_token_manager()
    info = token_manager.get_info(key)
    if not info or info.username != username:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "token"],
                "type": "not_found",
                "msg": "Token not found",
            },
        )
    return info


@router.delete("/users/{username}/tokens/{key}", status_code=204)
async def delete_token(
    username: str,
    key: str,
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> None:
    token_manager = context.factory.create_token_manager()
    info = token_manager.get_info(key)
    if info and info.username == username:
        success = await token_manager.delete_token(key, auth_data)
    else:
        success = False
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
)
async def patch_token(
    username: str,
    key: str,
    token_request: UserTokenModifyRequest,
    auth_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> TokenInfo:
    token_manager = context.factory.create_token_manager()
    info = token_manager.get_info(key)
    if not info or info.username != username:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={
                "loc": ["path", "token"],
                "type": "not_found",
                "msg": "Token not found",
            },
        )
    update = token_request.dict(exclude_unset=True)
    info = token_manager.modify_token(key, auth_data, **update)
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
