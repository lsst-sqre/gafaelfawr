"""Route handlers for the ``/auth/api/v1`` API.

All the route handlers are intentionally defined in a single file to encourage
the implementation to be very short.  All the business logic should be defined
in manager objects and the output formatting should be handled by response
models.
"""

from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends

from gafaelfawr.dependencies.auth import require_admin
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.models.admin import Admin

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
