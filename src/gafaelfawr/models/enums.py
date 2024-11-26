"""Enums used in Gafaelfawr models.

Notes
-----
These are kept in a separate module because some models need to import ORM
objects in order to define pagination cursors, but ORM objects often refer to
enums for column definitions.
"""

from __future__ import annotations

from enum import Enum

__all__ = [
    "AdminChange",
    "TokenChange",
    "TokenType",
]


class AdminChange(Enum):
    """Type of change made to a token admin."""

    add = "add"
    remove = "remove"


class TokenChange(Enum):
    """Type of change made to a token."""

    create = "create"
    revoke = "revoke"
    expire = "expire"
    edit = "edit"


class TokenType(Enum):
    """The class of token."""

    session = "session"
    """An interactive user web session."""

    user = "user"
    """A user-generated token that may be used programmatically."""

    notebook = "notebook"
    """The token delegated to a Jupyter notebook for the user."""

    internal = "internal"
    """Service-to-service token chained from a user request.

    A service-to-service token used for internal sub-calls made as part of
    processing a user request.
    """

    service = "service"
    """Service-to-service token independent of a user request.

    A service-to-service token used for internal calls initiated by
    services, unrelated to a user request.
    """

    oidc = "oidc"
    """Access token for an OpenID Connect client."""
