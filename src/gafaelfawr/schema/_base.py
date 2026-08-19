"""The base for the table schemas."""

from typing import ClassVar

from sqlalchemy import Text
from sqlalchemy.orm import DeclarativeBase

__all__ = ["SchemaBase"]


class SchemaBase(DeclarativeBase):
    """Declarative base for the Gafaelfawr database schema."""

    type_annotation_map: ClassVar = {str: Text()}
