"""Handler for generating an InfluxDB token (``/auth/tokens/influxdb/new``)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from safir.models import ErrorModel

from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import NotConfiguredException
from ..models.influxdb import InfluxDBToken
from ..models.token import TokenData

router = APIRouter()

__all__ = ["get_influxdb"]


@router.get(
    "/auth/tokens/influxdb/new",
    description="Construct a JWT for authentication to InfluxDB",
    response_model=InfluxDBToken,
    responses={
        404: {
            "description": "InfluxDB support not configured",
            "model": ErrorModel,
        },
    },
    summary="Create InfluxDB token",
    tags=["user"],
)
async def get_influxdb(
    token_data: TokenData = Depends(AuthenticateRead()),
    context: RequestContext = Depends(context_dependency),
) -> InfluxDBToken:
    """Return an InfluxDB-compatible JWT."""
    influxdb_service = context.factory.create_influxdb_service()
    try:
        influxdb_token = influxdb_service.issue_token(token_data)
    except NotConfiguredException as e:
        context.logger.warning("Not configured", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"type": "not_supported", "msg": str(e)},
        )
    username = influxdb_service.username_for_token(token_data)
    context.logger.info("Issued InfluxDB token", influxdb_username=username)
    return InfluxDBToken(token=influxdb_token)
