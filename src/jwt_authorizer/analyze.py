"""Token and ticket analysis.

Analyze tokens and tickets and display their contents and other debugging
information.
"""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import jwt

from jwt_authorizer.tokens import ALGORITHM

if TYPE_CHECKING:
    from jwt_authorizer.tokens import Ticket, TokenStore, TokenVerifier
    from typing import Any, Dict


def analyze_ticket(
    ticket: Ticket,
    prefix: str,
    token_store: TokenStore,
    token_verifier: TokenVerifier,
) -> Dict[str, Any]:
    """Analyze a ticket and return its expanded information.

    Parameters
    ----------
    ticket : `Ticket`
        The parsed ticket to analyze.
    prefix : `str`
        The prefix used for ticket handles.
    token_store : `TokenStore`
        The backend store used to retrieve the session for the ticket.
    token_verifier : `TokenVerifier`
        Verifier to check the validity of any underlying token.

    Returns
    -------
    output : `Dict` [`str`, `Any`]
        The contents of the ticket.  This will include the ticket ID and
        secret, the session it references, and the token that session
        contains.
    """
    output: Dict[str, Any] = {
        "ticket": {
            "ticket_id": ticket.ticket_id,
            "secret": base64.urlsafe_b64encode(ticket.secret).decode(),
        }
    }

    session = token_store.get_session(ticket)
    if not session:
        output["errors"] = [f"No session found for {ticket.as_handle(prefix)}"]
        return output

    output["session"] = {
        "email": session.email,
        "user": session.user,
        "created_at": session.created_at.strftime("%Y-%m-%d %H:%M:%S -0000"),
        "expires_on": session.expires_on.strftime("%Y-%m-%d %H:%M:%S -0000"),
    }

    output["token"] = analyze_token(session.token, token_verifier)

    return output


def analyze_token(token: str, token_verifier: TokenVerifier) -> Dict[str, Any]:
    unverified_token = jwt.decode(token, algorithms=ALGORITHM, verify=False)
    output = {
        "header": jwt.get_unverified_header(token),
        "data": unverified_token,
    }

    try:
        token_verifier.verify(token)
        output["valid"] = True
    except Exception as e:
        output["valid"] = False
        output["errors"] = [str(e)]

    return output
