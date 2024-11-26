"""Pydantic data types for Gafaelfawr models."""

from __future__ import annotations

from typing import Annotated, TypeAlias

from pydantic import PlainSerializer
from safir.pydantic import UtcDatetime

__all__ = ["Timestamp"]


Timestamp: TypeAlias = Annotated[
    UtcDatetime,
    PlainSerializer(lambda t: int(t.timestamp()), return_type=int),
]
"""Type for a `datetime` field that serializes to seconds since epoch."""
