"""Pydantic data types for Gafaelfawr models."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, TypeAlias

from pydantic import BeforeValidator, PlainSerializer
from safir.pydantic import normalize_datetime

__all__ = ["Timestamp"]


Timestamp: TypeAlias = Annotated[
    datetime,
    BeforeValidator(normalize_datetime),
    PlainSerializer(lambda t: int(t.timestamp()), return_type=int),
]
"""Type for a `datetime` field that only accepts seconds since epoch."""
