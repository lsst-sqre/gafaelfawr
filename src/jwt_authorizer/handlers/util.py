"""Utility functions for external routes."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web

from jwt_authorizer.authnz import (
    capabilities_from_groups,
    verify_authorization_strategy,
)
from jwt_authorizer.config import AuthenticateType

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from typing import Any, Dict, Mapping

__all__ = [
    "build_capability_headers",
    "forbidden",
    "unauthorized",
]


def build_capability_headers(
    request: web.Request, verified_token: Mapping[str, Any]
) -> Dict[str, str]:
    """Construct response headers containing capability information.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    verified_token : Mapping[`str`, Any]
        A verified token containing group and scope information.

    Returns
    -------
    headers : Dict[`str`, str]
        The headers to include in the response.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]

    capabilities_required, satisfy = verify_authorization_strategy(request)
    group_capabilities_set = capabilities_from_groups(
        verified_token, config.group_mapping
    )
    if "scope" in verified_token:
        scope_capabilities_set = set(verified_token["scope"].split(" "))
        user_capabilities_set = group_capabilities_set.union(
            scope_capabilities_set
        )
    else:
        user_capabilities_set = group_capabilities_set

    return {
        "X-Auth-Request-Token-Capabilities": " ".join(
            sorted(user_capabilities_set)
        ),
        "X-Auth-Request-Capabilities-Accepted": " ".join(
            sorted(capabilities_required)
        ),
        "X-Auth-Request-Capabilities-Satisfy": satisfy,
    }


def forbidden(
    request: web.Request, verified_token: Mapping[str, Any], error: str
) -> web.HTTPException:
    """Construct exception for a 403 response.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    verified_token : Mapping[`str`, Any]
        A verified token containing group and scope information.
    error : `str`
        The error message.

    Returns
    -------
    exception : `aiohttp.web.HTTPException`
        Exception to throw.
    """
    headers = build_capability_headers(request, verified_token)
    return web.HTTPForbidden(headers=headers, reason=error, text=error)


def unauthorized(
    request: web.Request, error: str, message: str = ""
) -> web.HTTPException:
    """Construct exception for a 401 response.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        The incoming request.
    error : `str`
        The error message to use as the body of the message and the error
        parameter in the WWW-Authenticate header.
    message : `str`, optional
        The error description for the WWW-Authetnicate header.

    Returns
    -------
    exception : `aiohttp.web.HTTPException`
        Exception to throw.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]

    headers = {}
    realm = config.realm
    if config.authenticate_type == AuthenticateType.Basic:
        headers["WWW-Authenticate"] = f'Basic realm="{realm}"'
    else:
        info = f'realm="{realm}",error="{error}",error_description="{message}"'
        headers["WWW-Authenticate"] = f"Bearer {info}"
    return web.HTTPUnauthorized(headers=headers, reason=error, text=error)
