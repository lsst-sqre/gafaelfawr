"""Handlers for the app's root, ``/``."""

from importlib.metadata import metadata
from typing import Dict, Optional

from fastapi import Depends
from pydantic import BaseModel
from safir.metadata import get_project_url

from gafaelfawr.config import Config
from gafaelfawr.fastapi.dependencies import config
from gafaelfawr.fastapi.handlers import router

__all__ = ["get_index"]


class Metadata(BaseModel):
    name: str
    version: str
    description: str
    repository_url: str
    documentation_url: str


@router.get("/", response_model=Metadata)
async def get_index(
    config: Config = Depends(config),
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
