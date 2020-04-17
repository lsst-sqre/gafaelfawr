"""Authentication and authorization functions."""

from __future__ import annotations

from typing import TYPE_CHECKING

from aiohttp import web

from jwt_authorizer.tokens import VerifiedToken

if TYPE_CHECKING:
    from jwt_authorizer.config import Config
    from logging import Logger
    from typing import List, Mapping, Set

__all__ = [
    "authorize",
    "scopes_from_token",
]


def authorize(request: web.Request, token: VerifiedToken) -> bool:
    """Authorize the request based on the token.

    Verify that the user authenticated by token has all of the scopes required
    by the request.

    Parameters
    ----------
    request : `aiohttp.web.Request`
        Incoming request.
    token : `jwt_authorizer.tokens.VerifiedToken`
        The verified token used for authorization.

    Returns
    -------
    success : `bool`
        Whether access is allowed.
    """
    config: Config = request.config_dict["jwt_authorizer/config"]
    logger: Logger = request["safir/logger"]

    # Determine the required scopes and authorization strategy from the
    # request.
    required_scopes = request.query.getall("scope", [])
    if not required_scopes:
        # Backward compatibility.  Can be removed when all deployments have
        # been updated.
        required_scopes = request.query.getall("capability", [])
    if not required_scopes:
        msg = "Neither scope nor capability set in the request"
        raise web.HTTPBadRequest(reason=msg, text=msg)
    satisfy = request.query.get("satisfy", "all")
    if satisfy not in ("any", "all"):
        msg = "satisfy parameter must be any or all"
        raise web.HTTPBadRequest(reason=msg, text=msg)

    # Determine whether the request is authorized.
    user_scopes = scopes_from_token(token, config.group_mapping)
    if satisfy == "any":
        success = any([scope in user_scopes for scope in required_scopes])
    else:
        success = all([scope in user_scopes for scope in required_scopes])

    # Log the results.
    jti = token.claims.get("jti", "UNKNOWN")
    user = token.claims[config.username_key]
    user_scopes_str = ", ".join(sorted(user_scopes))
    required_scopes_str = ", ".join(sorted(required_scopes))
    if success:
        logger.info(
            "Token %s (user: %s, scope: %s) authorized (needed %s of %s)",
            jti,
            user,
            user_scopes_str,
            satisfy,
            required_scopes_str,
        )
    else:
        logger.error(
            "Token %s (scope: %s) does not have %s of required scopes %s",
            jti,
            user_scopes_str,
            satisfy,
            required_scopes_str,
        )

    return success


def scopes_from_token(
    token: VerifiedToken, group_mapping: Mapping[str, List[str]]
) -> Set[str]:
    """Get scopes from a token.

    Parameters
    ----------
    token : `jwt_authorizer.tokens.VerifiedToken`
        The verified token.
    group_mapping : Mapping[`str`, List[`str`]]
        Mapping of capabilities to lists of groups that provide that
        capability.

    Returns
    -------
    scopes : Set[`str`]
        The union of the scopes specified in the scope claim and the scopes
        generated from the group membership based on the group_mapping
        parameter.
    """
    scopes = set(token.claims.get("scope", "").split())
    user_groups = {g["name"] for g in token.claims.get("isMemberOf", [])}
    for scope, granting_groups in group_mapping.items():
        for group in granting_groups:
            if group in user_groups:
                scopes.add(scope)
    return scopes
