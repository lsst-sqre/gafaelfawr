"""Handlers for the app's root, ``/``."""

from importlib.metadata import metadata
from typing import Dict, Optional

from fastapi import APIRouter, Depends
from safir.metadata import get_project_url

from gafaelfawr.config import Config
from gafaelfawr.dependencies.config import config_dependency
from gafaelfawr.models.app import Metadata

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
    summary="Application metadata",
    tags=["internal"],
)
async def get_index(
    config: Config = Depends(config_dependency),
) -> Dict[str, Optional[str]]:
    """GET ``/`` (the app's internal root).

    By convention, this endpoint returns only the application's metadata.
    """
    pkg_metadata = metadata("gafaelfawr")
    return {
        # Use configured name in case it is dynamically changed.
        "name": config.safir.name,
        # Get metadata from the package configuration
        "version": pkg_metadata.get("Version", "0.0.0"),
        "description": pkg_metadata.get("Summary", None),
        "repository_url": get_project_url(pkg_metadata, "Source code"),
        "documentation_url": pkg_metadata.get("Home-page", None),
    }
