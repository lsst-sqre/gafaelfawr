"""Handlers for the app's root, ``/``."""

from fastapi import APIRouter
from safir.metadata import Metadata, get_metadata
from safir.slack.webhook import SlackRouteErrorHandler

router = APIRouter(route_class=SlackRouteErrorHandler)

__all__ = ["get_index"]


@router.get(
    "/",
    description=(
        "Return metadata about the running application. Can also be used as"
        " a health check. This route is not exposed outside the cluster and"
        " therefore cannot be used by external clients."
    ),
    response_model=Metadata,
    response_model_exclude_none=True,
    summary="Application metadata",
    tags=["internal"],
)
async def get_index() -> Metadata:
    """GET ``/`` (the app's internal root).

    By convention, this endpoint returns only the application's metadata.
    """
    return get_metadata(
        package_name="gafaelfawr", application_name="gafaelfawr"
    )
