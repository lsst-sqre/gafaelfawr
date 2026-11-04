"""The base for the table schemas."""

from typing import Any, ClassVar, TypedDict

from sqlalchemy import JSON, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase

__all__ = ["INET_TYPE", "GitHubOwnerDict", "GroupDict", "SchemaBase"]

JSON_TYPE = JSON().with_variant(postgresql.JSONB, "postgresql")
"""Column type for JSON data, stored as JSONB on PostgreSQL."""

INET_TYPE = Text().with_variant(postgresql.INET, "postgresql")
"""Column type for IP addresses, stored as INET on PostgreSQL."""


class GitHubOwnerDict(TypedDict):
    """Serialized GitHub owner, as stored in a JSON column."""

    name: str
    """Login of the organization or user."""

    id: int
    """Numeric GitHub ID of the owner."""


class GroupDict(TypedDict):
    """Serialized group, as stored in a JSON column."""

    name: str
    """Name of the group."""

    id: int
    """Numeric GID of the group."""


class SchemaBase(DeclarativeBase):
    """Declarative base for the Gafaelfawr database schema."""

    type_annotation_map: ClassVar = {
        str: Text(),
        dict[str, Any]: JSON_TYPE,
        list[GitHubOwnerDict]: JSON_TYPE,
        list[GroupDict]: JSON_TYPE,
    }
