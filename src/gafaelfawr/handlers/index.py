"""Handlers for the app's root, ``/``."""

from email.message import Message
from importlib.metadata import metadata
from typing import cast

from fastapi import APIRouter
from safir.metadata import Metadata, get_project_url

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
async def get_index() -> Metadata:
    """GET ``/`` (the app's internal root).

    By convention, this endpoint returns only the application's metadata.
    """
    pkg_metadata = cast(Message, metadata("gafaelfawr"))
    return Metadata(
        name="gafaelfawr",
        version=pkg_metadata["Version"],
        description=pkg_metadata["Summary"],
        repository_url=get_project_url(pkg_metadata, "Source"),
        documentation_url=get_project_url(pkg_metadata, "Homepage"),
    )
