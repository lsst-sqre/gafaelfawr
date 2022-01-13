"""Handlers for the app's root, ``/``."""

from fastapi import APIRouter, Depends
from safir.metadata import Metadata, get_metadata

from ..config import Config
from ..dependencies.config import config_dependency

router = APIRouter()

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
async def get_index(config: Config = Depends(config_dependency)) -> Metadata:
    """GET ``/`` (the app's internal root).

    By convention, this endpoint returns only the application's metadata.
    """
    return get_metadata(
        package_name="gafaelfawr", application_name=config.safir.name
    )
