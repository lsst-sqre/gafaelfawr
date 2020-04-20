"""Token and ticket analysis.

Analyze tokens and tickets and display their contents and other debugging
information.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import jwt

from jwt_authorizer.constants import ALGORITHM

if TYPE_CHECKING:
    from jwt_authorizer.issuer import TokenIssuer
    from jwt_authorizer.session import SessionHandle, SessionStore
    from jwt_authorizer.tokens import Token
    from typing import Any, Dict

__all__ = ["analyze_handle", "analyze_token"]


async def analyze_handle(
    handle: SessionHandle, session_store: SessionStore, issuer: TokenIssuer,
) -> Dict[str, Any]:
    """Analyze a ticket and return its expanded information.

    Parameters
    ----------
    handle : `jwt_authorizer.session.SessionHandle`
        The parsed ticket to analyze.
    session_store : `jwt_authorizer.session.SessionStore`
        The backend store used to retrieve the session for the ticket.
    issuer : `jwt_authorizer.issuer.TokenIssuer`
        Issuer to check the validity of the token.

    Returns
    -------
    output : Dict[`str`, Any]
        The contents of the ticket.  This will include the ticket ID and
        secret, the session it references, and the token that session
        contains.
    """
    output: Dict[str, Any] = {
        "handle": {"key": handle.key, "secret": handle.secret}
    }

    session = await session_store.get_session(handle)
    if not session:
        output["errors"] = [f"No session found for {handle.encode()}"]
        return output

    output["session"] = {
        "email": session.email,
        "created_at": session.created_at.strftime("%Y-%m-%d %H:%M:%S -0000"),
        "expires_on": session.expires_on.strftime("%Y-%m-%d %H:%M:%S -0000"),
    }

    output["token"] = await analyze_token(session.token, issuer)

    return output


async def analyze_token(token: Token, issuer: TokenIssuer) -> Dict[str, Any]:
    """Analyze a token and return its expanded information.

    Parameters
    ----------
    token : `jwt_authorizer.tokens.Token`
        The encoded token to analyze.
    issuer : `jwt_authorizer.issuer.TokenIssuer`
        Issuer to check the validity of the token.

    Returns
    -------
    output : Dict[`str`, Any]
        The contents of the token.  This will include the capabilities and the
        header, a flag saying whether it is valid, and any errors.
    """
    unverified_token = jwt.decode(
        token.encoded, algorithms=ALGORITHM, verify=False
    )
    output = {
        "header": jwt.get_unverified_header(token.encoded),
        "data": unverified_token,
    }

    try:
        issuer.verify_token(token)
        output["valid"] = True
    except Exception as e:
        output["valid"] = False
        output["errors"] = [str(e)]

    return output
