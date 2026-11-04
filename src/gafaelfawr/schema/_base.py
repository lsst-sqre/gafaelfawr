"""The base for the table schemas."""

from typing import Any, ClassVar

from sqlalchemy import JSON, Text
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import DeclarativeBase

__all__ = ["INET_TYPE", "SchemaBase"]

JSON_TYPE = JSON().with_variant(postgresql.JSONB, "postgresql")
"""Column type for JSON data, stored as JSONB on PostgreSQL."""

INET_TYPE = Text().with_variant(postgresql.INET, "postgresql")
"""Column type for IP addresses, stored as INET on PostgreSQL."""


class SchemaBase(DeclarativeBase):
    """Declarative base for the Gafaelfawr database schema."""

    type_annotation_map: ClassVar = {
        str: Text(),
        dict[str, Any]: JSON_TYPE,
        list[dict[str, Any]]: JSON_TYPE,
    }
