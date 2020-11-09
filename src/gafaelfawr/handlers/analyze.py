"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import APIRouter, Depends, Form
from fastapi.responses import JSONResponse

from gafaelfawr.dependencies.auth import authenticate_session
from gafaelfawr.dependencies.context import RequestContext, context_dependency
from gafaelfawr.exceptions import InvalidTokenError
from gafaelfawr.models.token import Token, TokenData

router = APIRouter()

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


@router.get("/auth/analyze", response_class=FormattedJSONResponse)
async def get_analyze(
    token_data: TokenData = Depends(authenticate_session),
    context: RequestContext = Depends(context_dependency),
) -> Dict[str, Any]:
    """Analyze a token from a web session."""
    context.logger.info("Analyzed user session")
    return {
        "data": token_data.dict(),
        "valid": True,
    }


@router.post("/auth/analyze", response_class=FormattedJSONResponse)
async def post_analyze(
    token_str: str = Form(..., alias="token"),
    context: RequestContext = Depends(context_dependency),
) -> Dict[str, Any]:
    """Analyze a token.

    Expects a POST with a single parameter, ``token``, containing the token.
    Returns a JSON structure with details about that token.
    """
    try:
        token = Token.from_str(token_str)
    except InvalidTokenError as e:
        return {"errors": [str(e)], "valid": False}

    token_manager = context.factory.create_token_manager()
    token_data = await token_manager.get_data(token)
    if not token_data:
        return {
            "data": {"token": {"key": token.key, "secret": token.secret}},
            "errors": ["Invalid token"],
            "valid": False,
        }

    context.logger.info("Analyzed user-provided token")
    return {
        "data": token_data.dict(),
        "valid": True,
    }
