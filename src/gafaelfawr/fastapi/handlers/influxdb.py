"""Handler for generating an InfluxDB token (``/auth/tokens/influxdb/new``)."""

from __future__ import annotations

from typing import Dict

from fastapi import Depends, HTTPException, status
from pydantic import BaseModel

from gafaelfawr.exceptions import NotConfiguredException
from gafaelfawr.fastapi.auth import verified_token
from gafaelfawr.fastapi.dependencies import RequestContext, context
from gafaelfawr.fastapi.handlers import router
from gafaelfawr.tokens import VerifiedToken

__all__ = ["get_influxdb"]


class TokenReply(BaseModel):
    token: str


@router.get("/auth/tokens/influxdb/new", response_model=TokenReply)
async def get_influxdb(
    token: VerifiedToken = Depends(verified_token),
    context: RequestContext = Depends(context),
) -> Dict[str, str]:
    """Return an InfluxDB-compatible JWT.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    token : `gafaelfawr.tokens.VerifiedToken`
        The user's authentication token.

    Returns
    -------
    response : `aiohttp.web.Response`
        The response.
    """
    token_issuer = context.factory.create_token_issuer()
    try:
        influxdb_token = token_issuer.issue_influxdb_token(token)
    except NotConfiguredException as e:
        context.logger.warning("Not configured", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"type": "not_supported", "msg": str(e)},
        )
    if context.config.issuer.influxdb_username:
        username = context.config.issuer.influxdb_username
    else:
        username = token.username
    context.logger.info("Issued InfluxDB token", influxdb_username=username)
    return {"token": influxdb_token}
