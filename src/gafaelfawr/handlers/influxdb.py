"""Handler for generating an InfluxDB token (``/auth/tokens/influxdb/new``)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from safir.models import ErrorModel

from gafaelfawr.dependencies.auth import AuthenticateRead
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import NotConfiguredException
from gafaelfawr.models.influxdb import InfluxDBToken
from gafaelfawr.models.token import TokenData

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
    token_issuer = context.factory.create_token_issuer()
    try:
        influxdb_token = token_issuer.issue_influxdb_token(token_data)
    except NotConfiguredException as e:
        context.logger.warning("Not configured", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"type": "not_supported", "msg": str(e)},
        )
    if context.config.issuer.influxdb_username:
        username = context.config.issuer.influxdb_username
    else:
        username = token_data.username
    context.logger.info("Issued InfluxDB token", influxdb_username=username)
    return InfluxDBToken(token=influxdb_token)
