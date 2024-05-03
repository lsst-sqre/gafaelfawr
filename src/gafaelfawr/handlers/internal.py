"""Handlers for internal routes not exposed outside the cluster."""

from typing import Annotated

from fastapi import APIRouter, Depends
from safir.metadata import Metadata, get_metadata
from safir.slack.webhook import SlackRouteErrorHandler

from ..dependencies.context import RequestContext, context_dependency
from ..models.health import HealthCheck, HealthStatus

router = APIRouter(route_class=SlackRouteErrorHandler)

__all__ = ["router"]


@router.get(
    "/",
    description=(
        "Return metadata about the running application. This route is not"
        " exposed outside the cluster and therefore cannot be used by"
        " external clients."
    ),
    response_model=Metadata,
    response_model_exclude_none=True,
    summary="Application metadata",
    tags=["internal"],
)
async def get_index() -> Metadata:
    return get_metadata(
        package_name="gafaelfawr", application_name="gafaelfawr"
    )


@router.get(
    "/health",
    description="Perform an internal health check",
    response_model=HealthCheck,
    summary="Health check",
    tags=["internal"],
)
async def get_health(
    *,
    context: Annotated[RequestContext, Depends(context_dependency)],
) -> HealthCheck:
    health_check_service = context.factory.create_health_check_service()
    await health_check_service.check()
    return HealthCheck(status=HealthStatus.HEALTHY)
