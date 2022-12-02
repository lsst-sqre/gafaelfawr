"""Handler for token analysis (``/auth/analyze``)."""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Form
from fastapi.responses import JSONResponse

from ..dependencies.auth import AuthenticateRead
from ..dependencies.context import RequestContext, context_dependency
from ..exceptions import InvalidTokenError
from ..models.token import Token, TokenData
from ..slack import SlackRouteErrorHandler

router = APIRouter(route_class=SlackRouteErrorHandler)
authenticate = AuthenticateRead(
    require_session=True, redirect_if_unauthenticated=True
)
example_output = {
    "token": {
        "data": {
            "exp": 1616993932,
            "iat": 1614993932,
            "isMemberOf": [{"name": "g_special_users", "id": 139131}],
            "name": "Alice Example",
            "scope": "read:all user:token",
            "sub": "someuser",
            "uid": "someuser",
            "uidNumber": 4151,
        },
        "valid": False,
        "errors": ["Some error"],
    }
}


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


def token_data_to_analysis(token_data: TokenData) -> dict[str, dict[str, Any]]:
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
    "/auth/analyze",
    deprecated=True,
    description=(
        "Show a JSON dump of data about a user's cookie authentication.  The"
        " output format is for backwards compatibility with Gafaelfawr 1.x."
        " This route will be replaced with a more user-friendly debug page."
    ),
    response_class=FormattedJSONResponse,
    responses={
        200: {"content": {"application/json": {"example": example_output}}},
        307: {"description": "User is not authenticated"},
    },
    summary="Debug cookie authentication",
    tags=["user"],
)
async def get_analyze(
    token_data: TokenData = Depends(authenticate),
    context: RequestContext = Depends(context_dependency),
) -> dict[str, dict[str, Any]]:
    """Analyze a token from a web session."""
    return token_data_to_analysis(token_data)


@router.post(
    "/auth/analyze",
    deprecated=True,
    description=(
        "Show a JSON dump of data about the provided token.  The output"
        " format is for backwards compatibility with Gafaelfawr 1.x."
        " Use `/auth/api/v1/token-info` and `/auth/api/v1/user-info` instead."
    ),
    response_class=FormattedJSONResponse,
    responses={
        200: {"content": {"application/json": {"example": example_output}}},
    },
    summary="Debug a token",
    tags=["user"],
)
async def post_analyze(
    token_str: str = Form(
        ...,
        alias="token",
        title="Token to analyze",
        example="gt-db59fbkT5LrGHvhLMglNWw.G3NEmhWZr8JwO8AQ8sIWpQ",
    ),
    context: RequestContext = Depends(context_dependency),
) -> dict[str, dict[str, Any]]:
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
