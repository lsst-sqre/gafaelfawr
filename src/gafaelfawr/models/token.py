"""Representation of an authentication token."""

from __future__ import annotations

from enum import Enum

__all__ = ["TokenType"]


class TokenType(Enum):
    """The class of token.

    session
        An interactive user web session.
    user
        A user-generated token that may be used programmatically.
    notebook
        The token delegated to a Jupyter notebook for the user.
    internal
        A service-to-service token used for internal sub-calls made as part of
        processing a user request.
    """

    session = "session"
    user = "user"
    notebook = "notebook"
    internal = "internal"
