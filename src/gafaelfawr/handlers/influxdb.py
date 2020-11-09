"""Handler for generating an InfluxDB token (``/auth/tokens/influxdb/new``)."""

from __future__ import annotations

from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from gafaelfawr.dependencies.auth import authenticate
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import NotConfiguredException
from gafaelfawr.models.token import TokenData

router = APIRouter()

__all__ = ["get_influxdb"]


class TokenReply(BaseModel):
    token: str


@router.get("/auth/tokens/influxdb/new", response_model=TokenReply)
async def get_influxdb(
    token_data: TokenData = Depends(authenticate),
    context: RequestContext = Depends(context_dependency),
) -> Dict[str, str]:
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
    return {"token": influxdb_token}
