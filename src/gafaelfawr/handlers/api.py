"""Route handlers for the ``/auth/api/v1`` API.

All the route handlers are intentionally defined in a single file to encourage
the implementation to be very short.  All the business logic should be defined
in manager objects and the output formatting should be handled by response
models.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from gafaelfawr.dependencies.auth import authenticate, require_admin
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.models.admin import Admin
from gafaelfawr.models.token import TokenData, TokenInfo, TokenUserInfo

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
    "/token-info",
    response_model=TokenInfo,
    response_model_exclude_none=True,
    responses={404: {"description": "Token not found"}},
)
async def get_token_info(
    token_data: TokenData = Depends(authenticate),
    context: RequestContext = Depends(context_dependency),
) -> TokenInfo:
    token_manager = context.factory.create_token_manager()
    info = token_manager.get_info(token_data.token)
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
    token_data: TokenData = Depends(authenticate),
) -> TokenUserInfo:
    return token_data
