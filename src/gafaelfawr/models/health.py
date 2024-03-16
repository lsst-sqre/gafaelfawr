"""Models for health checks."""

from __future__ import annotations

from enum import Enum
from typing import Annotated

from pydantic import BaseModel, Field

__all__ = [
    "HealthCheck",
    "HealthStatus",
]


class HealthStatus(str, Enum):
    """Status of health check.

    Since errors are returned as HTTP 500 errors, currently the only status is
    the healthy status.
    """

    HEALTHY = "healthy"


class HealthCheck(BaseModel):
    """Results of an internal health check."""

    status: Annotated[HealthStatus, Field(title="Health status")]
