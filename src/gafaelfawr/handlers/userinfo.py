"""Handler for the user information route (``/auth/userinfo``)."""

from __future__ import annotations

from typing import Any, Mapping

from fastapi import APIRouter, Depends

from gafaelfawr.dependencies.auth import verified_token
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.tokens import VerifiedToken

router = APIRouter()

__all__ = ["get_userinfo"]


@router.get("/auth/userinfo")
async def get_userinfo(
    token: VerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context_dependency),
) -> Mapping[str, Any]:
    """Return information about the holder of a JWT."""
    context.logger.info("Returned user information")
    return token.claims
