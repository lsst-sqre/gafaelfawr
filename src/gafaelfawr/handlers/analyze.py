"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import APIRouter, Depends, Form
from fastapi.responses import JSONResponse

from gafaelfawr.dependencies.auth import Authenticate
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import InvalidTokenError
from gafaelfawr.models.token import Token, TokenData

router = APIRouter()
authenticate = Authenticate(
    require_session=True, redirect_if_unauthenticated=True
)

__all__ = ["get_analyze", "post_analyze"]


class FormattedJSONResponse(JSONResponse):
    """The same as `~fastapi.JSONResponse` except formatted for humans."""

    def render(self, content: Any) -> bytes:
        """Render a data structure into JSON formatted for humans."""
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=4,
            sort_keys=True,
        ).encode()


def token_data_to_analysis(token_data: TokenData) -> Dict[str, Dict[str, Any]]:
    """Convert the token data to the legacy analysis format.

    This produces the same format (with some missing data) as this route
    produced when all tokens were JWTs.  These routes are used by JupyterHub
    for authentication and expected the old format, so this is a backward
    compatibility shim.  This route can be dropped once JupyterHub has been
    converted to the new APIs and the UI provides a new way for a user to get
    information about their current session.
    """
    data = {
        "iat": int(token_data.created.timestamp()),
        "scope": " ".join(token_data.scopes),
        "sub": token_data.username,
        "uid": token_data.username,
    }
    if token_data.expires:
        data["exp"] = int(token_data.expires.timestamp())
    if token_data.groups:
        data["isMemberOf"] = [g.dict() for g in token_data.groups]
    if token_data.name:
        data["name"] = token_data.name
    if token_data.uid:
        data["uidNumber"] = str(token_data.uid)
    return {"token": {"data": data, "valid": True}}


@router.get(
    "/auth/analyze", response_class=FormattedJSONResponse, tags=["user"]
)
async def get_analyze(
    token_data: TokenData = Depends(authenticate),
    context: RequestContext = Depends(context_dependency),
) -> Dict[str, Dict[str, Any]]:
    """Analyze a token from a web session."""
    return token_data_to_analysis(token_data)


@router.post(
    "/auth/analyze", response_class=FormattedJSONResponse, tags=["user"]
)
async def post_analyze(
    token_str: str = Form(..., alias="token"),
    context: RequestContext = Depends(context_dependency),
) -> Dict[str, Dict[str, Any]]:
    """Analyze a token.

    Expects a POST with a single parameter, ``token``, containing the token.
    Returns a JSON structure with details about that token.
    """
    try:
        token = Token.from_str(token_str)
    except InvalidTokenError as e:
        return {"token": {"errors": [str(e)], "valid": False}}

    token_service = context.factory.create_token_service()
    token_data = await token_service.get_data(token)
    if not token_data:
        return {
            "handle": token.dict(),
            "token": {"errors": ["Invalid token"], "valid": False},
        }
    result = token_data_to_analysis(token_data)
    result["handle"] = token.dict()
    return result
